use nom::bytes::complete::{tag, take, take_until};
use nom::character::complete::one_of;
use nom::multi::{count, length_count, length_data};
use nom::number::complete::{le_u32, le_u64, u8};
use nom::IResult;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Endian {
    Little,
    Big,
}

fn null_terminated(i: &[u8]) -> IResult<&[u8], &[u8]> {
    let (i, str) = take_until(b"\0" as &[u8])(i)?;
    let (i, _) = tag(b"\0")(i)?;
    Ok((i, str))
}

pub fn parse_v6(i: &[u8]) -> IResult<&[u8], Vec<(u64, u64)>> {
    let (i, _magic) = tag(b"\x17\x08\x44tracing" as &[u8])(i)?;
    let (i, version) = null_terminated(i)?;
    let (i, endian) = u8(i)?;
    let endian = match endian {
        0 => Endian::Little,
        1 => Endian::Big,
        _ => unreachable!(),
    };
    assert!(endian == Endian::Little);
    let (i, long_size) = u8(i)?;
    let (i, page_size) = le_u32(i)?;
    let (i, _) = parse_header(i)?;
    let (i, _) = parse_ftrace_event_format(i)?;
    let (i, _) = parse_event_format(i)?;
    let (i, _) = parse_kallsyms(i)?;
    let (i, _) = parse_trace_printk(i)?;
    let (i, _) = parse_saved_cmdline(i)?;
    parse_header_tail(i)
}

fn parse_header(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _magic) = tag(b"header_page\0" as &[u8])(i)?;
    let (i, header_page) = length_data(le_u64)(i)?;
    let (i, _magic) = tag(b"header_event\0" as &[u8])(i)?;
    let (i, header_event) = length_data(le_u64)(i)?;
    Ok((i, ()))
}

fn parse_ftrace_event_format(i: &[u8]) -> IResult<&[u8], ()> {
    let each_event_format = |i| -> IResult<&[u8], ()> {
        let (i, data) = length_data(le_u64)(i)?;
        Ok((i, ()))
    };
    let (i, formats) = length_count(le_u32, each_event_format)(i)?;
    Ok((i, ()))
}

fn parse_event_format(i: &[u8]) -> IResult<&[u8], ()> {
    let each_event_format = |i| -> IResult<&[u8], ()> {
        let (i, data) = length_data(le_u64)(i)?;
        Ok((i, ()))
    };
    let each_system_format = |i| -> IResult<&[u8], ()> {
        let (i, name) = null_terminated(i)?;
        let (i, data) = length_count(le_u32, each_event_format)(i)?;
        Ok((i, ()))
    };
    let (i, formats) = length_count(le_u32, each_system_format)(i)?;
    Ok((i, ()))
}

fn parse_kallsyms(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, data) = length_data(le_u32)(i)?;
    Ok((i, ()))
}

fn parse_trace_printk(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, data) = length_data(le_u32)(i)?;
    Ok((i, ()))
}

fn parse_saved_cmdline(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, data) = length_data(le_u64)(i)?;
    Ok((i, ()))
}

fn parse_header_tail(i: &[u8]) -> IResult<&[u8], Vec<(u64, u64)>> {
    let (i, cpus) = le_u32(i)?;
    let (i, _skipped) = take_until(b"flyrecord\0" as &[u8])(i)?;
    let (i, _magic) = tag(b"flyrecord\0" as &[u8])(i)?;
    let each_cpu_offset = |i| -> IResult<&[u8], _> {
        let (i, offset) = le_u64(i)?;
        let (i, len) = le_u64(i)?;
        Ok((i, (offset, len)))
    };
    count(each_cpu_offset, cpus as usize)(i)
}
