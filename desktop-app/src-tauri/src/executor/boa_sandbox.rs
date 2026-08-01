use boa_engine::{js_string, property::Attribute, Context, JsValue, Source};
use std::cell::RefCell;
use tracing::info;
use super::ScriptExecutionResult;

thread_local! {
    static ENGINE_LOGS: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

pub fn run_boa_inner(script_code: &str, lux: f64, feed_data: &str) -> ScriptExecutionResult {
    info!("Executing Boa JS (lux={lux}, feed={feed_data})");
    ENGINE_LOGS.with(|l| l.borrow_mut().clear());
    let mut context = Context::default();
    context.runtime_limits_mut().set_loop_iteration_limit(100_000);
    let _ = context.register_global_property(js_string!("ambientLight"), JsValue::from(lux), Attribute::all());
    let _ = context.register_global_property(js_string!("feedData"), JsValue::from(js_string!(feed_data)), Attribute::all());

    let console_log = boa_engine::native_function::NativeFunction::from_fn_ptr(|_this, args, _ctx| {
        let msg = args.first().map(|v| v.display().to_string()).unwrap_or_default();
        info!("[Boa] {msg}");
        ENGINE_LOGS.with(|l| l.borrow_mut().push(msg));
        Ok(JsValue::undefined())
    });
    let func_obj = boa_engine::object::FunctionObjectBuilder::new(context.realm(), console_log).build();
    let _ = context.register_global_property(js_string!("log"), func_obj, Attribute::all());

    let get_ambient_light = boa_engine::native_function::NativeFunction::from_fn_ptr(|_this, _args, ctx| {
        let val = ctx.global_object().get(js_string!("ambientLight"), ctx).unwrap_or(JsValue::from(0.0));
        Ok(val)
    });
    let get_light_obj = boa_engine::object::FunctionObjectBuilder::new(context.realm(), get_ambient_light).build();
    let _ = context.register_global_property(js_string!("getAmbientLight"), get_light_obj, Attribute::all());

    let get_feed_data = boa_engine::native_function::NativeFunction::from_fn_ptr(|_this, _args, ctx| {
        let val = ctx.global_object().get(js_string!("feedData"), ctx).unwrap_or(JsValue::from(js_string!("")));
        Ok(val)
    });
    let get_feed_obj = boa_engine::object::FunctionObjectBuilder::new(context.realm(), get_feed_data).build();
    let _ = context.register_global_property(js_string!("getFeedData"), get_feed_obj, Attribute::all());

    let res = context.eval(Source::from_bytes(script_code.as_bytes()));
    let collected_logs = ENGINE_LOGS.with(|l| l.borrow().clone());
    match res {
        Ok(val) => ScriptExecutionResult { success: true, output: val.display().to_string(), logs: collected_logs },
        Err(e) => ScriptExecutionResult { success: false, output: format!("Error: {e}"), logs: vec![] },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_boa_basic() {
        let result = run_boa_inner("1 + 2", 0.0, "");
        assert!(result.success);
        assert_eq!(result.output, "3");
    }
    #[test]
    fn test_boa_ambient_light() {
        let result = run_boa_inner("ambientLight", 42.0, "");
        assert!(result.success);
        assert_eq!(result.output, "42");
    }
    #[test]
    fn test_boa_log() {
        let result = run_boa_inner("log('hello'); 'done'", 0.0, "");
        assert!(result.success);
        assert!(result.logs.iter().any(|l| l.contains("hello")));
    }
}
