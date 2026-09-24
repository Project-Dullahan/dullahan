use std::env;
use std::fs::{self, File};
use std::io::Write;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: nu_heal <target_file_path>");
        std::process::exit(1);
    }
    let file_path = &args[1];

    println!("🔮 [DULLAHAN NETWORK SUITE] Launching Reverse Compilation Fixer Engine...");
    
    // Read the raw truncated file text straight from disk
    let raw_content = match fs::read_to_string(file_path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("Fatal: Failed to read source target file. ({})", e);
            std::process::exit(1);
        }
    };

    let mut open_braces = 0;
    let mut open_parens = 0;

    // Execute the stack parser pass to find the unclosed delimiter layout bounds
    for character in raw_content.chars() {
        match character {
            '{' => open_braces += 1,
            '}' => if open_braces > 0 { open_braces -= 1; },
            '(' => open_parens += 1,
            ')' => if open_parens > 0 { open_parens -= 1; },
            _ => {}
        }
    }

    if open_braces == 0 && open_parens == 0 {
        println!("✦ Structure is already balanced. No syntax synthesis required.");
        return;
    }

    let mut healed_output = raw_content.clone();
    println!("✦ Unbalanced tokens detected: {} unclosed braces, {} unclosed parens.", open_braces, open_parens);

    // Run the synthesizer pass in reverse to fix the logical boundary
    if open_parens > 0 {
        healed_output.push_str(&")".repeat(open_parens));
    }
    if open_braces > 0 {
        healed_output.push_str("\n");
        healed_output.push_str(&"}".repeat(open_braces));
        healed_output.push_str("\n");
    }

    // Write the self-healed, balanced code block directly back onto the drive
    let mut file = File::create(file_path).expect("Failed to open file node for modification.");
    file.write_all(healed_output.as_bytes()).expect("Failed to commit synthesized source tree.");

    println!("✦ [HEAL SUCCESS] Trailing syntax boundaries appended. Tree structure is completely balanced!");
}
