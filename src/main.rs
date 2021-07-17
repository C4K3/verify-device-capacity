use anyhow::{bail, Context, Error, Result};

use rand_chacha::rand_core::RngCore;
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha12Rng;

use structopt::StructOpt;

use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Write a pseudorandom string of bytes to the given device. Then try to read them back to confirm
/// they match what was originally written.
#[derive(Debug, StructOpt)]
struct Args {
    /// Specify the seed. If set, the input is sha256-hashed and the hash is used as the RNG seed.
    ///
    /// Exclusive with --raw-seed
    ///
    /// If not specified, will generate a random seed.
    #[structopt(long = "seed")]
    seed: Option<String>,

    /// Specify the raw seed as a 32 byte value given in hexadecimal. Must be given as exactly 64
    /// characters with no leading 0x.
    ///
    /// Exclusive with --seed.
    #[structopt(long = "raw-seed")]
    raw_seed: Option<String>,

    /// Write to the given device.
    #[structopt(long = "write", short = "w")]
    write: bool,

    /// Read from the given device.
    #[structopt(long = "read", short = "r")]
    read: bool,

    /// The device to test.
    device: PathBuf,
}

fn main() -> Result<()> {
    _main()
}

fn _main() -> Result<()> {
    let mut args = Args::from_args();
    if !args.write && !args.read {
        args.write = true;
        args.read = true;
    }
    let args = args;

    let seed = get_seed(&args).context("Unable to get seed")?;
    if let Some(input_seed) = &args.seed {
        eprintln!("Using seed {}", input_seed);
    } else {
        eprintln!("Using raw seed {}", hex::encode(&seed));
    };
    let rng = ChaCha12Rng::from_seed(seed);

    let block_size = get_block_size(&args.device).with_context(|| {
        format!(
            "Unable to get block size of device at '{}'",
            args.device.display()
        )
    })?;

    if args.write {
        eprintln!("Will write random stream of data to device '{}'. This will overwrite all data on the device. Are you sure you want to continue? (y/N)", args.device.display());
        let mut response = String::new();
        std::io::stdin()
            .read_line(&mut response)
            .context("Error reading from stdin")?;
        let response = response.trim();
        if response != "y" && response != "Y" {
            bail!("Did not accept overwriting data on device. Safely exiting . . .");
        }
    }

    let mut written_bytes = None;
    if args.write {
        written_bytes = Some(
            write_device(&args, rng.clone(), block_size)
                .with_context(|| format!("Error writing to device '{}'", args.device.display()))?,
        );
    }

    let mut read_bytes = None;
    if args.read {
        read_bytes =
            Some(read_device(&args, rng, block_size).with_context(|| {
                format!("Error reading from device '{}'", args.device.display())
            })?);
    }
    if let (Some(written), Some(read)) = (written_bytes, read_bytes) {
        if written != read {
            bail!("Number of read bytes does not match number of written bytes. Wrote {} bytes but read {} bytes.", written, read);
        }
    }

    Ok(())
}

fn get_seed(args: &Args) -> Result<[u8; 32]> {
    use sha2::Digest;

    match (&args.seed, &args.raw_seed) {
        (Some(_), Some(_)) => {
            bail!("--seed and --raw-seed are mutually exclusive, please specify only one of them");
        }
        (Some(seed), None) => {
            let hash = sha2::Sha256::digest(seed.as_bytes());
            Ok(hash.try_into()?)
        }
        (None, Some(raw_seed)) => {
            if raw_seed.len() != 64 {
                bail!(
                    "--raw-seed has invalid length {}, expected 64 characters",
                    raw_seed.len()
                );
            }

            let mut buf = [0u8; 32];
            hex::decode_to_slice(raw_seed.as_bytes(), &mut buf)?;
            Ok(buf)
        }
        (None, None) => {
            if !args.write && args.read {
                bail!("Cannot read but not write when using random seed.");
            }
            Ok(rand::random())
        }
    }
}

fn get_block_size(path: &Path) -> Result<u64> {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::metadata(path)?;

    if !metadata.file_type().is_block_device() {
        bail!("Not a block device");
    }

    Ok(metadata.blksize())
}

fn write_device(args: &Args, mut rng: ChaCha12Rng, block_size: u64) -> Result<usize> {
    let mut d = File::create(&args.device)?;
    let mut buf = vec![0; block_size as usize];

    eprintln!("Writing to device {}", args.device.display());

    let mut written_bytes = 0;
    loop {
        rng.try_fill_bytes(&mut buf)?;

        let mut to_write = buf.as_slice();
        while !to_write.is_empty() {
            match d.write(to_write) {
                Ok(0) => {
                    bail!(
                        "Could not write any data to device. Had successfully written {} bytes.",
                        written_bytes
                    );
                }
                Ok(n) => {
                    written_bytes += n;
                    to_write = &to_write[n..];
                }
                Err(e) => {
                    if let Some(error_code) = e.raw_os_error() {
                        if error_code == 28 {
                            eprintln!("Successfully wrote {} bytes", written_bytes);
                            d.sync_all().context("Error while trying to call fsync")?;
                            return Ok(written_bytes);
                        }
                    }

                    return Err(Error::from(e).context(format!(
                        "Encountered error writing to device. Had successfully written {} bytes.",
                        written_bytes
                    )));
                }
            }
        }
    }
}

fn read_device(args: &Args, mut rng: ChaCha12Rng, block_size: u64) -> Result<usize> {
    let mut d = File::open(&args.device)?;
    let mut device_buf = vec![0; block_size as usize];
    let mut rng_buf = vec![0; block_size as usize];

    eprintln!("Reading from device {}", args.device.display());

    let mut read_bytes = 0;
    loop {
        let len = match d.read(&mut device_buf) {
            Ok(0) => {
                eprintln!("Successfully read and matched {} bytes", read_bytes);
                return Ok(read_bytes);
            }
            Ok(x) => x,
            Err(e) => {
                return Err(Error::from(e).context(format!(
                    "Encountered error reading device. Had successfully read {} bytes.",
                    read_bytes
                )));
            }
        };
        rng.try_fill_bytes(&mut rng_buf[..len])?;

        if device_buf[..len] != rng_buf[..len] {
            for i in 0..len {
                let a = &device_buf[i];
                let b = &rng_buf[i];
                if a != b {
                    bail!("Device found byte that does not match expected contents on position {}. Device had contents 0x{:02x}, but expected 0x{:02x}.", read_bytes + i, a, b);
                }
            }
            bail!("Unreachable. Unable to find mismatching bytes.");
        }

        read_bytes += len;
    }
}
