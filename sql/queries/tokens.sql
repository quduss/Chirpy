-- name: CreateRefreshToken :one
INSERT INTO refresh_tokens (token, user_id, expires_at)
VALUES ($1, $2, $3)
RETURNING *;

-- name: GetUserFromRefreshToken :one
SELECT u.* FROM users u
JOIN refresh_tokens rt ON rt.user_id = u.id
WHERE rt.token = $1 
  AND rt.expires_at > NOW()
  AND rt.revoked_at IS NULL;