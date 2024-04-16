# Rust Application

This application consists of two executables, `atm` and `bank`, which are built using Rust.

## Prerequisites

- Rust: You can download Rust from the [official website](https://www.rust-lang.org/tools/install).

## Building the Application

To compile the program, navigate to the directory containing the source code and run the following command:

```bash
cargo build --release
```

This will create the executable files `atm` and `bank` in the `target/release` directory.

## Running the Application

### Bank

To run the `bank` executable, use the following command:

```bash
./target/release/bank [-p <port>] [-s <auth-file>]
```

Replace `<port>` with the port number you want the bank server to listen on, and `<auth-file>` with the path to the file containing the authentication information.

### ATM

To run the `atm` executable, use one of the following commands depending on the operation you want to perform:

- **Check Balance**

  ```bash
  ./target/release/atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -n <balance>
  ```

- **Deposit Money**

  ```bash
  ./target/release/atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -d <amount>
  ```

- **Withdraw Money**

  ```bash
  ./target/release/atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -w <amount>
  ```

- **Get Account Details**

  ```bash
  ./target/release/atm [-s <auth-file>] [-i <ip-address>] [-p <port>] [-c <card-file>] -a <account> -g
  ```

In these commands, replace `<auth-file>` with the path to the file containing the authentication information, `<ip-address>` with the IP address of the bank server, `<port>` with the port number of the bank server, `<card-file>` with the path to the file containing the card information, `<account>` with the account name, `<balance>` with the balance amount, and `<amount>` with the deposit or withdrawal amount.
