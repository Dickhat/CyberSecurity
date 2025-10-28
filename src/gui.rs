pub mod greet_screen;
pub mod cryptography;

use greet_screen::Credentials;
use cryptography::Cryptography;

pub enum GUI 
{
    Autorhization(Credentials),
    Cryptography(Cryptography)
}