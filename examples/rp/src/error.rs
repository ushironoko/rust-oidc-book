use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

pub fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("ログイン処理が開始されていないか、すでに使われました")]
    NoPendingLogin,
    #[error("state が一致しません")]
    StateMismatch,
    #[error("認可レスポンスの iss が一致しません")]
    IssuerMismatch,
    #[error("OP がエラーを返しました: {0}")]
    AuthorizationDenied(String),
    #[error("認可レスポンスに code がありません")]
    MissingCode,
    #[error("認可コードをトークンに交換できませんでした: {0}")]
    TokenExchange(String),
    #[error("IDトークンの検証に失敗しました: {0}")]
    IdToken(String),
    #[error("UserInfo の取得に失敗しました: {0}")]
    UserInfo(String),
    #[error("ログインしていません")]
    NotLoggedIn,
    #[error("処理中のログインが多すぎます。時間をおいてやり直してください")]
    TooManyPendingLogins,
    #[error("セッションの操作に失敗しました: {0}")]
    Session(#[from] tower_sessions::session::Error),
    #[error("リソースサーバとの通信に失敗しました: {0}")]
    Api(#[from] reqwest::Error),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match self {
            AppError::NotLoggedIn => StatusCode::UNAUTHORIZED,
            AppError::TooManyPendingLogins => StatusCode::SERVICE_UNAVAILABLE,
            AppError::Session(_) | AppError::Api(_) | AppError::TokenExchange(_) => StatusCode::BAD_GATEWAY,
            _ => StatusCode::BAD_REQUEST,
        };
        println!("[rp] {status} {self}");
        // error_description など OP や攻撃者が決められる文字列を含むので、HTML として解釈させない
        let message = escape(&self.to_string());
        (status, Html(format!("<!doctype html><meta charset=\"utf-8\"><h1>エラー</h1><p>{message}</p>"))).into_response()
    }
}
