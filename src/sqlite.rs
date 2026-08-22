use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::ptr;

const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;

#[repr(C)]
struct Sqlite3 {
    _private: [u8; 0],
}

#[repr(C)]
struct Sqlite3Statement {
    _private: [u8; 0],
}

#[link(name = "sqlite3")]
extern "C" {
    fn sqlite3_open(filename: *const c_char, database: *mut *mut Sqlite3) -> c_int;
    fn sqlite3_close(database: *mut Sqlite3) -> c_int;
    fn sqlite3_errmsg(database: *mut Sqlite3) -> *const c_char;
    fn sqlite3_exec(
        database: *mut Sqlite3,
        sql: *const c_char,
        callback: *mut c_void,
        callback_argument: *mut c_void,
        error_message: *mut *mut c_char,
    ) -> c_int;
    fn sqlite3_prepare_v2(
        database: *mut Sqlite3,
        sql: *const c_char,
        sql_bytes: c_int,
        statement: *mut *mut Sqlite3Statement,
        tail: *mut *const c_char,
    ) -> c_int;
    fn sqlite3_finalize(statement: *mut Sqlite3Statement) -> c_int;
    fn sqlite3_reset(statement: *mut Sqlite3Statement) -> c_int;
    fn sqlite3_clear_bindings(statement: *mut Sqlite3Statement) -> c_int;
    fn sqlite3_bind_int64(statement: *mut Sqlite3Statement, index: c_int, value: i64) -> c_int;
    fn sqlite3_bind_text(
        statement: *mut Sqlite3Statement,
        index: c_int,
        value: *const c_char,
        length: c_int,
        destructor: Option<unsafe extern "C" fn(*mut c_void)>,
    ) -> c_int;
    fn sqlite3_step(statement: *mut Sqlite3Statement) -> c_int;
    fn sqlite3_column_int64(statement: *mut Sqlite3Statement, column: c_int) -> i64;
    fn sqlite3_column_text(statement: *mut Sqlite3Statement, column: c_int) -> *const u8;
    fn sqlite3_column_bytes(statement: *mut Sqlite3Statement, column: c_int) -> c_int;
    fn sqlite3_libversion() -> *const c_char;
}

pub struct Database {
    pointer: *mut Sqlite3,
    cached_query: *mut Sqlite3Statement,
}

impl Database {
    pub fn in_memory() -> Result<Self, String> {
        let filename = CString::new(":memory:").map_err(|error| error.to_string())?;
        let mut pointer = ptr::null_mut();
        let status = unsafe { sqlite3_open(filename.as_ptr(), &mut pointer) };
        if status != SQLITE_OK || pointer.is_null() {
            return Err("SQLite could not open an in-memory database".to_string());
        }
        Ok(Self {
            pointer,
            cached_query: ptr::null_mut(),
        })
    }

    pub fn execute_batch(&mut self, sql: &str) -> Result<(), String> {
        let sql = CString::new(sql).map_err(|error| error.to_string())?;
        let status = unsafe {
            sqlite3_exec(
                self.pointer,
                sql.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        self.status(status)
    }

    pub fn insert_fixture_row(
        &mut self,
        statement: &mut Statement,
        values: [i64; 6],
        title: &str,
    ) -> Result<(), String> {
        statement.reset(self)?;
        for (offset, value) in values.into_iter().enumerate() {
            statement.bind_i64(
                self,
                c_int::try_from(offset + 1).unwrap_or(c_int::MAX),
                value,
            )?;
        }
        statement.bind_text(self, 7, title)
    }

    pub fn prepare(&mut self, sql: &str) -> Result<Statement, String> {
        Statement::new(self, sql)
    }

    pub fn query_rows(
        &mut self,
        sql: &str,
        arguments: [i64; 4],
        cached: bool,
    ) -> Result<Vec<crate::database::DbRow>, String> {
        let mut rows = Vec::new();
        self.query_rows_visit(
            sql,
            arguments,
            cached,
            |id, owner, score, updated_at, title| {
                rows.push(crate::database::DbRow {
                    id,
                    owner,
                    score,
                    updated_at,
                    title: title.to_string(),
                });
                Ok(())
            },
        )?;
        Ok(rows)
    }

    pub fn query_rows_visit<F>(
        &mut self,
        sql: &str,
        arguments: [i64; 4],
        cached: bool,
        mut visitor: F,
    ) -> Result<usize, String>
    where
        F: FnMut(u32, u16, u16, u64, &str) -> Result<(), String>,
    {
        if cached {
            if self.cached_query.is_null() {
                self.cached_query = self.prepare_raw(sql)?;
            }
            let pointer = self.cached_query;
            self.query_with_visit(pointer, arguments, &mut visitor)
        } else {
            let pointer = self.prepare_raw(sql)?;
            let result = self.query_with_visit(pointer, arguments, &mut visitor);
            let status = unsafe { sqlite3_finalize(pointer) };
            if result.is_ok() {
                self.status(status)?;
            }
            result
        }
    }

    fn query_with_visit<F>(
        &mut self,
        statement: *mut Sqlite3Statement,
        arguments: [i64; 4],
        visitor: &mut F,
    ) -> Result<usize, String>
    where
        F: FnMut(u32, u16, u16, u64, &str) -> Result<(), String>,
    {
        self.status(unsafe { sqlite3_reset(statement) })?;
        self.status(unsafe { sqlite3_clear_bindings(statement) })?;
        for (offset, value) in arguments.into_iter().enumerate() {
            self.status(unsafe {
                sqlite3_bind_int64(
                    statement,
                    c_int::try_from(offset + 1).unwrap_or(c_int::MAX),
                    value,
                )
            })?;
        }

        let mut row_count = 0usize;
        loop {
            let status = unsafe { sqlite3_step(statement) };
            if status == SQLITE_DONE {
                break;
            }
            if status != SQLITE_ROW {
                return Err(self.error());
            }
            let id = checked_u32(unsafe { sqlite3_column_int64(statement, 0) }, "id")?;
            let owner = checked_u16(unsafe { sqlite3_column_int64(statement, 1) }, "owner")?;
            let score = checked_u16(unsafe { sqlite3_column_int64(statement, 2) }, "score")?;
            let updated_at =
                checked_u64(unsafe { sqlite3_column_int64(statement, 3) }, "updated_at")?;
            let title_pointer = unsafe { sqlite3_column_text(statement, 4) };
            let title_length = unsafe { sqlite3_column_bytes(statement, 4) };
            if title_pointer.is_null() || title_length < 0 {
                return Err("SQLite returned an invalid title".to_string());
            }
            let title = unsafe {
                std::slice::from_raw_parts(
                    title_pointer,
                    usize::try_from(title_length).map_err(|error| error.to_string())?,
                )
            };
            visitor(
                id,
                owner,
                score,
                updated_at,
                std::str::from_utf8(title).map_err(|error| error.to_string())?,
            )?;
            row_count = row_count.saturating_add(1);
        }
        Ok(row_count)
    }

    fn prepare_raw(&mut self, sql: &str) -> Result<*mut Sqlite3Statement, String> {
        let sql = CString::new(sql).map_err(|error| error.to_string())?;
        let mut statement = ptr::null_mut();
        let status = unsafe {
            sqlite3_prepare_v2(
                self.pointer,
                sql.as_ptr(),
                c_int::try_from(sql.as_bytes().len()).map_err(|error| error.to_string())?,
                &mut statement,
                ptr::null_mut(),
            )
        };
        self.status(status)?;
        if statement.is_null() {
            return Err("SQLite returned no prepared statement".to_string());
        }
        Ok(statement)
    }

    fn status(&self, status: c_int) -> Result<(), String> {
        if status == SQLITE_OK {
            Ok(())
        } else {
            Err(self.error())
        }
    }

    fn error(&self) -> String {
        let pointer = unsafe { sqlite3_errmsg(self.pointer) };
        if pointer.is_null() {
            "SQLite returned an unknown error".to_string()
        } else {
            unsafe { CStr::from_ptr(pointer) }
                .to_string_lossy()
                .into_owned()
        }
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        if !self.cached_query.is_null() {
            let _ = unsafe { sqlite3_finalize(self.cached_query) };
        }
        if !self.pointer.is_null() {
            let _ = unsafe { sqlite3_close(self.pointer) };
        }
    }
}

pub struct Statement {
    pointer: *mut Sqlite3Statement,
}

impl Statement {
    fn new(database: &mut Database, sql: &str) -> Result<Self, String> {
        Ok(Self {
            pointer: database.prepare_raw(sql)?,
        })
    }

    fn reset(&mut self, database: &Database) -> Result<(), String> {
        database.status(unsafe { sqlite3_reset(self.pointer) })?;
        database.status(unsafe { sqlite3_clear_bindings(self.pointer) })
    }

    fn bind_i64(&mut self, database: &Database, index: c_int, value: i64) -> Result<(), String> {
        database.status(unsafe { sqlite3_bind_int64(self.pointer, index, value) })
    }

    fn bind_text(&mut self, database: &Database, index: c_int, value: &str) -> Result<(), String> {
        let value = CString::new(value).map_err(|error| error.to_string())?;
        let status = unsafe {
            sqlite3_bind_text(
                self.pointer,
                index,
                value.as_ptr(),
                c_int::try_from(value.as_bytes().len()).map_err(|error| error.to_string())?,
                None,
            )
        };
        database.status(status)?;
        let step = unsafe { sqlite3_step(self.pointer) };
        if step != SQLITE_DONE {
            return Err(database.error());
        }
        database.status(unsafe { sqlite3_clear_bindings(self.pointer) })?;
        database.status(unsafe { sqlite3_reset(self.pointer) })?;
        Ok(())
    }
}

impl Drop for Statement {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            let _ = unsafe { sqlite3_finalize(self.pointer) };
        }
    }
}

pub fn version() -> String {
    let pointer = unsafe { sqlite3_libversion() };
    if pointer.is_null() {
        "unavailable".to_string()
    } else {
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }
}

fn checked_u16(value: i64, field: &str) -> Result<u16, String> {
    u16::try_from(value).map_err(|_| format!("SQLite {field} is outside u16"))
}

fn checked_u32(value: i64, field: &str) -> Result<u32, String> {
    u32::try_from(value).map_err(|_| format!("SQLite {field} is outside u32"))
}

fn checked_u64(value: i64, field: &str) -> Result<u64, String> {
    u64::try_from(value).map_err(|_| format!("SQLite {field} is outside u64"))
}
