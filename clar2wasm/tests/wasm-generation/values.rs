use clar2wasm::tools::{crosscheck, TestEnvironment};
use clarity::vm::Value;
use proptest::prelude::ProptestConfig;
use proptest::proptest;
use proptest::strategy::Strategy;

use crate::{PropValue, TypePrinter};

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 500,
        .. ProptestConfig::default()
    })]
    #[test]
    fn evaluated_value_is_the_value_itself(val in PropValue::any()) {
        crosscheck(
            &val.to_string(),
            Ok(Some(val.into()))
        )
    }

    #[test]
    fn value_serialized_and_deserialized(val in PropValue::any().prop_filter("Filter condition description", |val| {
        let mut env = TestEnvironment::default();
        env.evaluate(&format!("(to-consensus-buff? {val})")).is_ok()
    })) {
        println!("Snippet:{:?}",&format!("(from-consensus-buff? {} (unwrap-panic (to-consensus-buff? {})))", val.type_string() ,val));
        crosscheck(
            &format!("(from-consensus-buff? {} (unwrap-panic (to-consensus-buff? {})))", val.type_string() ,val),
            Ok(Some(Value::some(val.into()).unwrap()))
        )
    }
}
