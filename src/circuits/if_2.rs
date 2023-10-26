use ark_ff::PrimeField;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::AllocVar;
use ark_r1cs_std::prelude::EqGadget;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_relations::r1cs::ConstraintSystemRef;
use ark_relations::r1cs::SynthesisError;

// if age > 19 
//    c ?= a * b
// else
//    nothing

#[derive(Clone)]
pub struct IfV2<F: PrimeField> {
    // statement
    age: Option<F>,
    c: Option<F>,
    //witness
    a: Option<F>,
    b: Option<F>,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for IfV2<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        let age = FpVar::new_input(cs.clone(), || self.age.ok_or(SynthesisError::AssignmentMissing))?;
        
        let age19 = F::from_str("19").unwrap_or_default();
        let age19 = FpVar::new_constant(cs.clone(), age19)?;

        let is_age_greater_then19 = age.is_cmp(&age19, std::cmp::Ordering::Greater, false)?;


        let c = FpVar::new_input(cs.clone(), || self.c.ok_or(SynthesisError::AssignmentMissing))?;
        
        let a = FpVar::new_input(cs.clone(), || self.a.ok_or(SynthesisError::AssignmentMissing))?;
        let b = FpVar::new_input(cs.clone(), || self.b.ok_or(SynthesisError::AssignmentMissing))?;
        

        c.conditional_enforce_equal(&(a*b), &is_age_greater_then19)?;

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use std::str::FromStr;

    use ark_bn254::Fr;
    use ark_ff::Fp;
    use ark_relations::r1cs::ConstraintSynthesizer;

    use crate::circuits::if_2::IfV2;

    #[test]
    fn test_mul() {
        let age: Fr = Fp::from_str("19").unwrap();
        let a: Fr = Fp::from_str("3").unwrap();
        let b: Fr = Fp::from_str("3").unwrap();

        let c: Fr = Fp::from_str("6").unwrap();

        let test_circuit = IfV2 {age: Some(age), a: Some(a), b: Some(b), c: Some(c)};
        let cs = ark_relations::r1cs::ConstraintSystem::new_ref();

        test_circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }
}
