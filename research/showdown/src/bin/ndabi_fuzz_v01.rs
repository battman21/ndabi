//! Run the repeatable NDABI parser mutation campaign.

use ndabi_showdown::fuzz_v01;

const DEFAULT_SEED: u64 = 0x4e44_4142_495f_465a;
const DEFAULT_CASES: u64 = 100_000;

fn main() -> Result<(), String> {
    let (seed, cases) = arguments()?;
    let report = fuzz_v01::run(seed, cases)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn arguments() -> Result<(u64, u64), String> {
    let mut seed = DEFAULT_SEED;
    let mut cases = DEFAULT_CASES;
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("{argument} requires a value"))?;
        match argument.as_str() {
            "--seed" => {
                seed = value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --seed: {error}"))?;
            }
            "--cases" => {
                cases = value
                    .parse::<u64>()
                    .map_err(|error| format!("invalid --cases: {error}"))?;
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok((seed, cases))
}
