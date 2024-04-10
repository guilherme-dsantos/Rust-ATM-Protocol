use std::str::FromStr;

pub fn validate_number(s: &str, balance: bool) -> bool{
    let pattern = regex::Regex::new(r"^(0|[1-9][0-9]*)\.[0-9]{2}$").unwrap();
    match pattern.is_match(s) {
        true => {
            let value = match f64::from_str(s) {
                Ok(v) => v,
                Err(_) => {
                    //eprintln!("Failed to parse balance as a float.");
                    return false;
                }
            };
            if !(0.00..=4294967295.99).contains(&value) {
                return false;
            }
            if balance && value < 10.00 {
                return false;
            }
        }
        false => {
            //eprintln!("Not a match");
            return false;
        }
    }
    true
}

pub fn validate_ip_address(s: &str) -> bool{
    let pattern = regex::Regex::new(r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$").unwrap();
    if !pattern.is_match(s) {
       // eprintln!("{}", &s);
        return false;
    }
    true
}

pub fn validate_port(s: &str) -> bool{
    if let Ok(port) = s.parse::<u16>() {
        //u16 goes to 65535
        if port < 1024 {
            //eprintln!("Port number out of valid range (1024-65535).");
            return false;
        }
    } else {
        //eprintln!("Invalid input: not a number or too big.");
        return false;
    }
    true
}
pub fn validate_account(account_name: &str) -> bool{
    let valid_pattern = regex::Regex::new(r"^[_\-\.0-9a-z]+$").unwrap();
    let is_valid_length = !account_name.is_empty() && account_name.len() <= 122;
    let is_valid_name = valid_pattern.is_match(account_name);

    if !(is_valid_length && is_valid_name) {
        //eprintln!("Invalid account name: {}", account_name);
        return false;
    }
    true
}

pub fn validate_file_name(file_name: &str) -> bool{
    let valid_pattern = regex::Regex::new(r"^[_\-\.0-9a-z]+$").unwrap();
    let is_valid_length = !file_name.is_empty() && file_name.len() <= 127;
    let is_valid_name = valid_pattern.is_match(file_name);
    let is_not_special = file_name != "." && file_name != "..";
    if !(is_valid_length && is_valid_name && is_not_special) {
        return false;
    }
    true
}