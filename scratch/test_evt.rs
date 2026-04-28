use windows::core::*;
use windows::Win32::System::EventLog::*;
use windows::Win32::Foundation::HANDLE;

fn main() {
    unsafe {
        let channel = w!("System");
        let query = w!("*[System[TimeCreated[timediff(@SystemTime) <= 600000]]]");

        let handle = EvtQuery(
            None,
            channel,
            query,
            EvtQueryChannelPath.0 | EvtQueryReverseDirection.0,
        );

        // Wait, EvtQuery signature might take PCWSTR or HSTRING.
    }
}
