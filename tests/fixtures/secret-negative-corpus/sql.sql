SELECT u.id, u.email, count(k.id) AS keys
FROM users u
LEFT JOIN api_keys k ON k.user_id = u.id AND k.revoked_at IS NULL
WHERE u.created_at > now() - interval '30 days'
GROUP BY u.id, u.email
ORDER BY keys DESC
LIMIT 50;

UPDATE sessions SET expires_at = now() WHERE id = '336f1ef5-63ef-4822-9618-97aa93033cb7';
INSERT INTO audit_log (id, actor, action, target) VALUES ('2f8dc5a3-bde0-4215-94a0-b07d985f619a', 'system', 'rotate', 'webhook');
