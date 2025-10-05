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

-- name: RevokeRefreshToken :exec
-- Revokes a refresh token by setting revoked_at and updated_at
-- This effectively "logs out" the user from this session
UPDATE refresh_tokens 
SET revoked_at = NOW(), 
    updated_at = NOW()
WHERE token = $1;