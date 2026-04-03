use chrono::{DateTime, Utc};
use evtx::EvtxParser;
use serde::Serialize;
use std::env;
use std::convert::TryInto; // Add this import for .try_into()

#[derive(Debug, Serialize)]
struct EventRecord {
    timestamp: Option<DateTime<Utc>>,
    event_id: u32, // This expects a u32
    description: String,
    user: Option<String>,
    logon_type: Option<String>,
    ip: Option<String>,
}
 
fn get_description(event_id: u32) -> &'static str { // This expects a u32
    match event_id {
        12 => "System Start",
        13 => "System Shutdown",
        6005 => "Event Log Service Started",
        6006 => "Event Log Service Stopped",
        6008 => "Unexpected Shutdown",
        1074 => "Planned Shutdown/Restart",
        4624 => "Logon Success",
        4634 => "Logoff",
        4647 => "User Initiated Logoff",
        4648 => "Explicit Credential Logon",
        4800 => "Workstation Locked",
        4801 => "Workstation Unlocked",
        _ => "Other",
    }
}
 
fn parse_evtx(path: &str) -> Vec<EventRecord> {
    let mut parser = EvtxParser::from_path(path).unwrap();
    let mut results = Vec::new();
 
    for record in parser.records() {
        if let Ok(rec) = record {
            // Get the raw event_record_id (likely u64)
            let raw_event_id = rec.event_record_id;

            // Attempt to convert to u32, handle potential overflow gracefully
            let event_id: u32 = match raw_event_id.try_into() {
                Ok(id) => id,
                Err(_) => {
                    // Log an error or warning, or skip the record if the ID is too large
                    // For now, we'll just skip this record if the ID doesn't fit in u32
                    // You might want a more sophisticated error handling here.
                    eprintln!("Warning: Event record ID {} is too large to fit in u32. Skipping record.", raw_event_id);
                    continue;
                }
            };
            
            // Only process relevant Event IDs - use the *converted* `event_id` variable
            if ![
                12, 13, 6005, 6006, 6008, 1074,
                4624, 4634, 4647, 4648, 4800, 4801
            ].contains(&event_id) { // <-- FIX: Changed from `&rec.event_id` to `&event_id`
                continue;
            }
 
            let data = rec.data; // This is a String, representing the XML or JSON data inside the event.
 
            let timestamp = rec.timestamp; // This is a DateTime<Utc>
 
            // Extract fields
            let mut user = None;
            let mut logon_type = None;
            let mut ip = None;
            
            // The `data` field of `SerializedEvtxRecord` is often a raw XML or JSON string.
            // You need to parse it to a `serde_json::Value` to use `.get("EventData")`.
            // The `evtx` crate might provide helpers for this, but if `data` is a String,
            // then `data.get("EventData")` won't work directly because `String` does not
            // implement `Index<str>` for getting elements.
            // Assuming `data` is a JSON string, you need to parse it first:
            if let Ok(json_data) = serde_json::from_str::<serde_json::Value>(&data) {
                if let Some(event_data) = json_data.get("EventData") { // <-- FIX: `json_data.get()`
                    if let Some(map) = event_data.as_object() {
                        user = map.get("TargetUserName")
                            .and_then(|v| v.as_str())
                            .map(String::from);
     
                        logon_type = map.get("LogonType")
                            .and_then(|v| v.as_str())
                            .map(String::from);
     
                        ip = map.get("IpAddress")
                            .and_then(|v| v.as_str())
                            .map(String::from);
                    }
                }
            } else {
                // If `data` is not valid JSON, or you want to handle XML,
                // you would add parsing logic here. For now, we'll just skip
                // extraction if JSON parsing fails.
                eprintln!("Warning: Failed to parse event data as JSON for event ID {}. Data: {:?}", event_id, data);
            }
 
            results.push(EventRecord {
                timestamp: Some(timestamp), // <-- FIX: Wrapped in Some()
                event_id, // <-- FIX: Used the converted `event_id` variable
                description: get_description(event_id).to_string(), // <-- FIX: Used the converted `event_id` variable
                user,
                logon_type,
                ip,
            });
        }
    }
 
    results
}

 
fn main() {
    let args: Vec<String> = env::args().collect();
 
    if args.len() < 2 {
        println!("Usage: evtx_parser <file1.evtx> <file2.evtx>");
        return;
    }
 
    let mut all_events: Vec<EventRecord> = Vec::new();
 
    for file in &args[1..] {
        println!("[+] Parsing {}", file);
        let mut events = parse_evtx(file);
        all_events.append(&mut events);
    }
 
    // Sort by timestamp
    all_events.sort_by_key(|e| e.timestamp);
 
    println!("\n==== Timeline ====\n");
 
    for e in all_events {
        println!(
            "{:?} | {} | {} | User: {:?} | LogonType: {:?} | IP: {:?}",
            e.timestamp, e.event_id, e.description, e.user, e.logon_type, e.ip
        );
    }
}
