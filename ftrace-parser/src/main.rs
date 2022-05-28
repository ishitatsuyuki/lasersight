use ftrace_parser::parse_v6;
use nom::IResult;
use std::env::args;
use std::fs::read;

fn main() {
    let (i, offsets) = parse_v6(&read(&args().collect::<Vec<_>>()[1]).unwrap()).unwrap();
    dbg!(offsets);
}
