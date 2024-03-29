use clap::{App, Arg};

pub fn cli() -> Result<clap::ArgMatches, clap::Error> {
    let matches = App::new("bank")
        .arg(
            Arg::with_name("port")
                .short('p')
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("auth-file")
                .short('s')
                .takes_value(true)
                .required(true),
        )
        .try_get_matches();
    matches
}