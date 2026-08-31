//! Measure the dynamic ISA control path without database execution.
//!
//! This diagnostic separates verification, PostgreSQL lowering, and cached lookup.
//! It does not claim database, transport, or complete workflow performance.

use std::hint::black_box;
use std::time::{Duration, Instant};

use ndabi_isa::{
    verify_operands, verify_program, Comparison, Field, OperandBuilder, ParameterDescriptor,
    ParameterValue, ProgramBuilder, ProgramCache, Relation, ScalarType, Schema, SortDirection,
    SortTerm, VerifyLimits,
};
use ndabi_postgres::isa::{
    lower_verified_program, FieldBinding, PostgresCatalogue, RelationBinding,
};
use ndabi_protocol::{cached_dynamic_frame_bytes, dynamic_frame_bytes};

const READ: u64 = 1;
const WARM_UPS: usize = 1_024;
const EXECUTIONS: usize = 100_000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let schema = Schema::new(vec![Relation::new(
        11,
        READ,
        vec![
            Field::new(101, ScalarType::I64, false, READ)?,
            Field::new(102, ScalarType::Utf8, false, READ)?,
            Field::new(103, ScalarType::U64, false, READ)?,
        ],
    )?])?;
    let catalogue = PostgresCatalogue::new(
        &schema,
        vec![RelationBinding::new(
            11,
            "public",
            "events",
            vec![
                FieldBinding::new(101, "event_id")?,
                FieldBinding::new(102, "summary")?,
                FieldBinding::new(103, "created_at")?,
            ],
        )?],
    )?;
    let program = dynamic_program(&schema)?;
    let verified = verify_program(&program, &schema, READ, VerifyLimits::default())?;
    let mut operand_builder = OperandBuilder::new(&verified);
    operand_builder.push(ParameterValue::I64(50))?;
    operand_builder.push(ParameterValue::U64(25))?;
    let operand_bytes = operand_builder.finish()?;
    let verified_operands = verify_operands(&operand_bytes, &verified)?;
    let lowered = lower_verified_program(&verified, &catalogue)?;
    let mut cache = ProgramCache::new([9; 32], 16)?;
    let promotion = cache.promote(&verified, lowered)?;

    for _ in 0..WARM_UPS {
        black_box(verify_program(
            black_box(&program),
            black_box(&schema),
            READ,
            VerifyLimits::default(),
        )?);
        black_box(lower_verified_program(
            black_box(&verified),
            black_box(&catalogue),
        )?);
        black_box(verify_operands(
            black_box(&operand_bytes),
            black_box(&verified),
        )?);
        black_box(cache.resolve(promotion.handle, verified.digest())?);
    }

    let verification = elapsed(|| {
        black_box(
            verify_program(
                black_box(&program),
                black_box(&schema),
                READ,
                VerifyLimits::default(),
            )
            .expect("the frozen diagnostic program must verify"),
        );
    });
    let lowering = elapsed(|| {
        black_box(
            lower_verified_program(black_box(&verified), black_box(&catalogue))
                .expect("the verified diagnostic program must lower"),
        );
    });
    let operand_verification = elapsed(|| {
        black_box(
            verify_operands(black_box(&operand_bytes), black_box(&verified))
                .expect("the frozen operand block must verify"),
        );
    });
    let cached = elapsed(|| {
        black_box(
            cache
                .resolve(promotion.handle, verified.digest())
                .expect("the promoted program must resolve"),
        );
    });

    println!("dynamic_program_bytes={}", program.len());
    println!("instruction_count={}", verified.instruction_count());
    println!("parameter_count={}", verified.parameter_count());
    println!("operand_block_bytes={}", operand_bytes.len());
    let full_frame_bytes = dynamic_frame_bytes(program.len(), operand_bytes.len())?;
    let cached_frame_bytes = cached_dynamic_frame_bytes(verified_operands.compact_bytes().len())?;
    println!("full_dynamic_frame_bytes={full_frame_bytes}");
    println!("cached_dynamic_frame_bytes={cached_frame_bytes}");
    println!(
        "cached_frame_reduction_percent={:.2}",
        100.0 * (full_frame_bytes - cached_frame_bytes) as f64 / full_frame_bytes as f64
    );
    println!("verification_ns_per_operation={}", nanos(verification));
    println!(
        "operand_verification_ns_per_operation={}",
        nanos(operand_verification)
    );
    println!("lowering_ns_per_operation={}", nanos(lowering));
    println!("cached_lookup_ns_per_operation={}", nanos(cached));
    println!("database_execution_measured=false");
    Ok(())
}

fn elapsed(mut operation: impl FnMut()) -> Duration {
    let start = Instant::now();
    for _ in 0..EXECUTIONS {
        operation();
    }
    start.elapsed()
}

fn nanos(duration: Duration) -> u128 {
    duration.as_nanos() / EXECUTIONS as u128
}

fn dynamic_program(schema: &Schema) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut builder = ProgramBuilder::new(schema.digest(), 32)?;
    let minimum = builder.parameter(ParameterDescriptor::new(ScalarType::I64, 8)?)?;
    let limit = builder.parameter(ParameterDescriptor::new(ScalarType::U64, 8)?)?;
    let scan = builder.scan(11)?;
    let filter = builder.filter(scan, 101, Comparison::GreaterOrEqual, minimum)?;
    let project = builder.project(filter, &[101, 102])?;
    let sort = builder.sort(
        project,
        &[SortTerm {
            field: 101,
            direction: SortDirection::Descending,
        }],
    )?;
    let limit = builder.limit(sort, limit)?;
    builder.return_result(limit)?;
    Ok(builder.finish()?)
}
