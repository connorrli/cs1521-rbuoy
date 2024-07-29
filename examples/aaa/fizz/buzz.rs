// crab
fn main() {
    for i in 1.. {
        match (i % 3, i % 5) {
            (0, 0) => println!("fizz buzz!"),
            (0, _) => println!("fizz..."),
            (_, 0) => println!("buzz?"),
            (_, _) => println!("{i}"),
        }
    }
}