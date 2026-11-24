use crate::models::ExecutionLog;
use axum::http::StatusCode;
use chrono::Utc;
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

const MAX_JOBS_PER_USER: usize = 50;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundJob {
    pub id: String,
    pub user_id: String,
    pub username: String,
    pub title: String,
    pub command_names: Vec<String>,
    pub target_labels: Vec<String>,
    pub total_targets: usize,
    pub completed_targets: usize,
    pub success_count: usize,
    pub failed_count: usize,
    pub status: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub timeout_sec: u64,
    pub estimated_timeout_sec: u64,
    pub read: bool,
    pub error_message: Option<String>,
    pub results: Vec<ExecutionLog>,
}

#[derive(Clone, Default)]
pub struct BackgroundJobStore {
    inner: Arc<RwLock<Vec<BackgroundJob>>>,
}

impl BackgroundJobStore {
    pub async fn active_count(&self) -> usize {
        let jobs = self.inner.read().await;
        jobs.iter().filter(|j| j.status == "running").count()
    }

    pub async fn active_count_for_user(&self, user_id: &str) -> usize {
        let jobs = self.inner.read().await;
        jobs.iter()
            .filter(|j| j.user_id == user_id && j.status == "running")
            .count()
    }

    pub async fn try_start(
        &self,
        job: BackgroundJob,
        max_limit_per_user: usize,
    ) -> Result<(BackgroundJob, usize), usize> {
        let mut jobs = self.inner.write().await;
        let user_id = job.user_id.clone();
        let user_active = jobs
            .iter()
            .filter(|j| j.user_id == user_id && j.status == "running")
            .count();
        if user_active >= max_limit_per_user {
            return Err(user_active);
        }
        let snapshot = job.clone();
        jobs.insert(0, job);

        let mut seen_for_user = 0usize;
        jobs.retain(|item| {
            if item.user_id != user_id {
                return true;
            }
            seen_for_user += 1;
            item.status == "running" || seen_for_user <= MAX_JOBS_PER_USER
        });

        let next_user_active = jobs
            .iter()
            .filter(|j| j.user_id == user_id && j.status == "running")
            .count();
        Ok((snapshot, next_user_active))
    }

    pub async fn record_result(&self, job_id: &str, log: ExecutionLog) {
        let mut jobs = self.inner.write().await;
        if let Some(job) = jobs.iter_mut().find(|j| j.id == job_id) {
            job.completed_targets += 1;
            if log.exit_code == 0 {
                job.success_count += 1;
            } else {
                job.failed_count += 1;
            }
            job.results.push(log);
        }
    }

    pub async fn finish(&self, job_id: &str, started_epoch_ms: i64, fatal_error: Option<String>) {
        let mut jobs = self.inner.write().await;
        if let Some(job) = jobs.iter_mut().find(|j| j.id == job_id) {
            let now = Utc::now();
            job.finished_at = Some(now.to_rfc3339());
            job.duration_ms = Some((now.timestamp_millis() - started_epoch_ms).max(0) as u64);
            if let Some(err) = fatal_error {
                job.status = "failed".to_string();
                job.error_message = Some(err);
            } else if job.failed_count == 0 {
                job.status = "completed".to_string();
            } else if job.success_count > 0 {
                job.status = "partial".to_string();
            } else {
                job.status = "failed".to_string();
            }
        }
    }

    pub async fn list_for_user(&self, user_id: &str) -> (Vec<BackgroundJob>, usize, usize, usize) {
        let jobs = self.inner.read().await;
        let total_active_count = jobs.iter().filter(|j| j.status == "running").count();
        let user_jobs: Vec<BackgroundJob> = jobs
            .iter()
            .filter(|j| j.user_id == user_id)
            .cloned()
            .collect();
        let user_active_count = user_jobs.iter().filter(|j| j.status == "running").count();
        let unread_count = user_jobs
            .iter()
            .filter(|j| j.status != "running" && !j.read)
            .count();
        (user_jobs, user_active_count, total_active_count, unread_count)
    }

    pub async fn list_all(&self) -> (Vec<BackgroundJob>, usize) {
        let jobs = self.inner.read().await;
        let active_count = jobs.iter().filter(|j| j.status == "running").count();
        let mut all_jobs: Vec<BackgroundJob> = jobs.iter().cloned().collect();
        all_jobs.sort_by(|a, b| {
            let a_run = a.status == "running";
            let b_run = b.status == "running";
            match (a_run, b_run) {
                (true, false) => std::cmp::Ordering::Less,
                (false, true) => std::cmp::Ordering::Greater,
                _ => b.started_at.cmp(&a.started_at),
            }
        });
        (all_jobs, active_count)
    }

    pub async fn get_for_user(&self, user_id: &str, job_id: &str) -> Option<BackgroundJob> {
        let jobs = self.inner.read().await;
        jobs.iter()
            .find(|j| j.id == job_id && j.user_id == user_id)
            .cloned()
    }

    pub async fn mark_read(&self, user_id: &str, job_id: &str) -> Option<(BackgroundJob, usize)> {
        let mut jobs = self.inner.write().await;
        let mut found: Option<BackgroundJob> = None;
        for job in jobs.iter_mut() {
            if job.id == job_id && job.user_id == user_id {
                job.read = true;
                found = Some(job.clone());
                break;
            }
        }
        let job = found?;
        let unread = jobs
            .iter()
            .filter(|j| j.user_id == user_id && j.status != "running" && !j.read)
            .count();
        Some((job, unread))
    }

    pub async fn mark_all_read(&self, user_id: &str) -> usize {
        let mut jobs = self.inner.write().await;
        for job in jobs.iter_mut() {
            if job.user_id == user_id && job.status != "running" {
                job.read = true;
            }
        }
        0
    }

    pub async fn delete_for_user(
        &self,
        user_id: &str,
        job_id: &str,
    ) -> Result<(), (StatusCode, &'static str)> {
        let mut jobs = self.inner.write().await;
        let Some(pos) = jobs
            .iter()
            .position(|j| j.id == job_id && j.user_id == user_id)
        else {
            return Err((StatusCode::NOT_FOUND, "Hintergrundauftrag nicht gefunden."));
        };
        if jobs[pos].status == "running" {
            return Err((
                StatusCode::CONFLICT,
                "Ein noch laufender Hintergrundauftrag kann nicht entfernt werden.",
            ));
        }
        jobs.remove(pos);
        Ok(())
    }
}
