# Aetheris IAM — Frontend Console

A React (Vite + TypeScript) single-page admin console for the IAM platform, styled
with Tailwind CSS and the Aetheris brand. It talks to the API gateway and covers
authentication, users, roles, permissions, groups, tenants, and MFA.

## Stack

- **Vite + React 18 + TypeScript**
- **Tailwind CSS** (custom `brand` gold + `ink` slate palette, Inter font)
- **react-router-dom** for routing with protected routes
- **lucide-react** icons

## Pages

| Route             | Description                                              |
| ----------------- | -------------------------------------------------------- |
| `/login`          | Sign in (email/password + organization), with MFA step   |
| `/forgot-password`| Request a password-reset link                            |
| `/reset-password` | Set a new password from an emailed token                 |
| `/`               | Dashboard with stat cards and recent activity            |
| `/users`          | List/search/paginate, create/edit/deactivate, assign roles |
| `/roles`          | Create/edit/delete roles and attach permissions          |
| `/permissions`    | Browse the permission catalog, create new permissions    |
| `/groups`         | Create groups (role bundles) and add members             |
| `/tenants`        | Provision and suspend/activate tenants                   |
| `/security`       | Profile, change password, MFA enrollment (QR + recovery) |

## Configuration

Copy `.env.example` to `.env` and adjust if needed:

```
VITE_API_BASE=http://localhost:8080   # API gateway base URL
VITE_DEFAULT_TENANT=aetheris              # default org slug on the login screen
```

## Logo

Place the Aetheris logo at `public/logo.png`. If the file is missing, the UI falls
back to a gold "AT" monogram + wordmark automatically.

## Local development

```bash
cd frontend
npm install
npm run dev          # http://localhost:5173
```

Make sure the backend stack is running (`docker compose up -d` from the repo root)
so the gateway is reachable at `http://localhost:8080`.

## Production build

```bash
npm run build        # outputs to dist/
npm run preview      # serve the production build locally
```

## Docker

The console is wired into the root `docker-compose.yml` as the `frontend` service
(served by nginx on port **3000**):

```bash
docker compose up -d --build frontend
# open http://localhost:3000
```
