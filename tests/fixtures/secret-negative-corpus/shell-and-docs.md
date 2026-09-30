## Quick start

```sh
export API_KEY="<your API key>"
export STRIPE_SECRET_KEY=$STRIPE_SECRET_KEY
curl https://api.example.com/v1/health
curl -s "https://api.example.com/v1/blocks?limit=5" | jq .
git clone https://github.com/example/project.git && cd project
docker pull quay.io/example/api@sha256:a26fb1d9ac46016831bfb622fc740a683d0aca36d53417ddfbaa29f4a1be2d02
```

Replace `YOUR_API_KEY` with the key from the dashboard. Keys look like
`sk-...` for the model provider and `gm_live_...` for gm; never commit them.
Token limits: `max_tokens` defaults to 4096 and `context_tokens` to 131072.

| Setting | Default |
|---|---|
| `password_min_length` | 12 |
| `token_ttl_seconds` | 3600 |
| `secret_rotation_days` | 90 |
