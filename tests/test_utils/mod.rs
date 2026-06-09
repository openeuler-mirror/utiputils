/*
 * SPDX-FileCopyrightText: 2025 UnionTech Software Technology Co., Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

use std::process::{Command, Output};
use std::str;
use std::time::Duration;

pub struct TestCommand {
    pub command: String,
    pub args: Vec<String>,
    pub timeout: Duration,
}

impl TestCommand {
    pub fn new_utping(args: &[&str]) -> Self {
        let mut full_args = vec!["./target/debug/utping".to_string()];
        full_args.extend(args.iter().map(|s| s.to_string()));

        Self {
            command: "sudo".to_string(),
            args: full_args,
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn execute(&self) -> Result<TestOutput, String> {
        let timeout_secs = self.timeout.as_secs().max(1);
        let timeout_arg = format!("{}s", timeout_secs);

        let output = Command::new(&self.command)
            .args(["timeout", timeout_arg.as_str()])
            .args(&self.args)
            .output()
            .map_err(|e| format!("Failed to execute command: {}", e))?;

        Ok(TestOutput::new(output))
    }
}

pub struct TestOutput {
    pub stdout: String,
    pub stderr: String,
    pub success: bool,
}

impl TestOutput {
    fn new(output: Output) -> Self {
        Self {
            stdout: str::from_utf8(&output.stdout)
                .unwrap_or("Invalid UTF-8 in stdout")
                .to_string(),
            stderr: str::from_utf8(&output.stderr)
                .unwrap_or("Invalid UTF-8 in stderr")
                .to_string(),
            success: output.status.success(),
        }
    }

    pub fn assert_stdout_contains(&self, text: &str) -> &Self {
        assert!(
            self.stdout.contains(text),
            "STDOUT does not contain '{}' (success={})\nSTDOUT:\n{}\nSTDERR:\n{}",
            text,
            self.success,
            self.stdout,
            self.stderr
        );
        self
    }

    pub fn assert_stdout_not_contains(&self, text: &str) -> &Self {
        assert!(
            !self.stdout.contains(text),
            "STDOUT should not contain '{}' (success={})\nSTDOUT:\n{}\nSTDERR:\n{}",
            text,
            self.success,
            self.stdout,
            self.stderr
        );
        self
    }

    fn find_position(&self, text: &str) -> Option<usize> {
        self.stdout.find(text)
    }

    pub fn find_line_containing(&self, text: &str) -> Option<&str> {
        self.stdout.lines().find(|line| line.contains(text))
    }

    pub fn assert_order(&self, first: &str, second: &str) -> &Self {
        let first_pos = self
            .find_position(first)
            .unwrap_or_else(|| panic!("First text '{}' not found in output", first));
        let second_pos = self
            .find_position(second)
            .unwrap_or_else(|| panic!("Second text '{}' not found in output", second));

        assert!(
            first_pos < second_pos,
            "'{}' should appear before '{}' in output\nSTDOUT:\n{}",
            first,
            second,
            self.stdout
        );
        self
    }
}

// 确保 utping 已编译的辅助函数
pub fn ensure_utping_compiled() -> Result<(), String> {
    let output = Command::new("cargo")
        .args(["build", "--bin", "utping"])
        .output()
        .map_err(|e| format!("Failed to run cargo build: {}", e))?;

    if !output.status.success() {
        let stderr = str::from_utf8(&output.stderr).unwrap_or("Unknown error");
        return Err(format!("Failed to compile utping: {}", stderr));
    }

    Ok(())
}
