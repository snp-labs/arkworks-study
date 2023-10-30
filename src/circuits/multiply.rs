use ark_ff::Field;

use ark_relations::lc;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::SynthesisError;

// c =? a * b
#[derive(Clone)]
pub struct MultiplyCircuit<F: Field> {
    // statement
    c: Option<F>,
    // witness
    a: Option<F>,
    b: Option<F>,
}

impl<F: Field> ConstraintSynthesizer<F> for MultiplyCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // input statements
        // const
        // witness

        let c = cs.new_input_variable(|| self.c.ok_or(SynthesisError::AssignmentMissing))?;
        
        let a = cs.new_witness_variable(|| self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| self.b.ok_or(SynthesisError::AssignmentMissing))?;
        
        cs.enforce_constraint(
            lc!() + a,
            lc!() + b,
            lc!() + c,
        )?;

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use std::str::FromStr;

    use ark_bn254::Fr;
    use ark_ff::Fp;
    use ark_relations::r1cs::ConstraintSynthesizer;

    use crate::circuits::multiply::MultiplyCircuit;

    #[test]
    fn test_mul() {
        let a: Fr = Fp::from_str("3").unwrap();
        let b: Fr = Fp::from_str("3").unwrap();

        let c: Fr = Fp::from_str("6").unwrap();

        let test_circuit = MultiplyCircuit {a: Some(a), b: Some(b), c: Some(c)};
        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();

        test_circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
