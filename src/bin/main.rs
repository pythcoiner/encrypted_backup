use clap::Parser;
use clap::Subcommand;

use encrypted_backup::Error;
use encrypted_backup::decrypt;
use encrypted_backup::encrypt;

use miniscript::Descriptor;
use miniscript::DescriptorPublicKey;
use miniscript::bitcoin::bip32::Xpub;

use std::env;
use std::fmt::write;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug)]
pub enum CliError {
    CantConvertToDescriptor(miniscript::Error),
    CantConvertToXpub(miniscript::bitcoin::bip32::Error),
    EmptyDescriptor,
    CwdError(std::io::Error),
    CreateError(std::io::Error),
    OpenError(std::io::Error),
    WriteError(std::io::Error),
    ReadError(std::io::Error),
    FailedToEncrypt(encrypted_backup::Error),
    FailedToDecrypt(encrypted_backup::Error),
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::CantConvertToDescriptor(err) => {
                write!(f, "Can't convert to a descriptor: {err:?}")
            }
            CliError::CantConvertToXpub(err) => {
                write!(f, "Can't  convert to master public key: {err:?}")
            }
            CliError::EmptyDescriptor => write!(f, "Empty descriptor"),
            CliError::CwdError(err) => write!(f, "Cant find current working directiory: {err:?}"),
            CliError::CreateError(err) => write!(f, "Cannot create file: {err:?}"),
            CliError::OpenError(err) => write!(f, "Cannot open file: {err:?}"),
            CliError::WriteError(err) => write!(f, "Cannot write file: {err:?}"),
            CliError::ReadError(err) => write!(f, "Cannot read file: {err:?}"),
            CliError::FailedToEncrypt(err) => write!(f, "Cannot encrypt: {err:?}"),
            CliError::FailedToDecrypt(err) => write!(f, "Cannot decrypt: {err:?}"),
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Encrypt some descriptor
    Encrypt {
        /// Input file containing the descriptor
        #[arg(short, long)]
        file: Option<String>,

        /// Optional output to encrypted descriptor
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Decrypt an encrypted descriptor with a given xpub
    Decrypt {
        /// Input file to be decrypted
        #[arg(short, long)]
        file: Option<String>,

        /// The key containing a xpub
        #[arg(short, long)]
        key: Option<String>,

        /// Optional decrypted descriptor
        #[arg(short, long)]
        output: Option<String>,
    },
}

fn main() -> Result<(), CliError> {
    let cli = Cli::parse();

    // Handle the specific subcommand
    match &cli.command {
        Commands::Encrypt { file, output } => {
            let input_path = match file {
                Some(path) => {
                    let mut descriptor_path = PathBuf::new();
                    descriptor_path.push(path);
                    descriptor_path
                }
                None => {
                    let mut descriptor_path = env::current_dir().map_err(CliError::CwdError)?;
                    descriptor_path.push("descriptor.txt");
                    descriptor_path
                }
            };

            let output_path = match output {
                Some(path) => {
                    let mut output_path = PathBuf::new();
                    output_path.push(path);
                    output_path
                }
                None => {
                    let mut output_path = env::current_dir().map_err(CliError::CwdError)?;
                    output_path.push("descriptor.bin");
                    output_path
                }
            };

            let data = fs::read_to_string(&input_path).map_err(CliError::ReadError)?;

            // The read descritor need to be readed with a trimmed white space
            let descriptor = Descriptor::<DescriptorPublicKey>::from_str(&data.trim())
                .map_err(CliError::CantConvertToDescriptor)?;

            // encrypt the descriptor
            let encrypted = encrypt(descriptor).map_err(CliError::FailedToEncrypt)?;

            // pass the byte vector to a file
            let mut output = File::create(&output_path).map_err(CliError::CreateError)?;
            output.write(&encrypted).map_err(CliError::WriteError)?;
            println!("descriptor written to {output_path:?}");
        }
        Commands::Decrypt { file, key, output } => {
            let input_path = match file {
                Some(path) => {
                    let mut descriptor_path = PathBuf::new();
                    descriptor_path.push(path);
                    descriptor_path
                }
                None => {
                    let mut descriptor_path = env::current_dir().map_err(CliError::CwdError)?;
                    descriptor_path.push("descriptor.txt");
                    descriptor_path
                }
            };

            let output_path = match output {
                Some(path) => {
                    let mut output_path = PathBuf::new();
                    output_path.push(path);
                    output_path
                }
                None => {
                    let mut output_path = env::current_dir().map_err(CliError::CwdError)?;
                    output_path.push("descriptor.txt");
                    output_path
                }
            };

            let key_path = match key {
                Some(path) => {
                    let mut xpub_path = PathBuf::new();
                    xpub_path.push(path);
                    xpub_path
                }
                None => {
                    let mut xpub_path = env::current_dir().map_err(CliError::CwdError)?;
                    xpub_path.push("xpub.txt");
                    xpub_path
                }
            };

            let data = fs::read(&input_path).map_err(CliError::ReadError)?;
            let key = fs::read_to_string(key_path).map_err(CliError::ReadError)?;
            let xpub = Xpub::from_str(key.trim()).map_err(CliError::CantConvertToXpub)?;
            let decrypted = decrypt(xpub, data)
                .map_err(CliError::FailedToDecrypt)?
                .to_string();
            fs::write(&output_path, &decrypted).map_err(CliError::WriteError)?;
            println!("descriptor written to {output_path:?}");
        }
    }
    Ok(())
}
