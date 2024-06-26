use clap::{App, Arg, ArgGroup};

pub fn cli() -> Result<clap::ArgMatches, clap::Error> {
    let matches = App::new("atm")
        .arg(
            Arg::with_name("auth-file")
                .short('s')
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("ip-address")
                .short('i')
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("port")
                .short('p')
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("card-file")
                .short('c')
                .takes_value(true)
                .required(false),
        )
        .arg(
            Arg::with_name("account")
                .short('a')
                .takes_value(true)
                .required(true),
        )
        .group(
            ArgGroup::with_name("operation")
                .required(true)
                .args(&["balance", "deposit", "withdraw", "get"]),
        )
        .arg(
            Arg::with_name("balance")
                .short('n')
                .takes_value(true)
                .requires("account")
                .conflicts_with_all(&["deposit", "withdraw", "get"]),
        )
        .arg(
            Arg::with_name("deposit")
                .short('d')
                .takes_value(true)
                .requires("account")
                .conflicts_with_all(&["balance", "withdraw", "get"]),
        )
        .arg(
            Arg::with_name("withdraw")
                .short('w')
                .takes_value(true)
                .requires("account")
                .conflicts_with_all(&["balance", "deposit", "get"]),
        )
        .arg(
            Arg::with_name("get")
                .short('g')
                .conflicts_with_all(&["balance", "deposit", "withdraw"]),
        )
        .try_get_matches();
    
    // Check if the total length of all arguments exceeds 4096 characters
    //Ex: Execution "cargo run --bin atm -- -a bob -n 140.00" has a length of 33 -> target\debug\atm.exe-abob-n140.00
    let total_length: usize = std::env::args().map(|arg| arg.len()).sum();
    if total_length > 4096 {
        return Err(clap::Error::with_description(
            "".to_owned(),
            clap::ErrorKind::InvalidValue,
        ));
    }

    matches
}
