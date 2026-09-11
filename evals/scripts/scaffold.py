#!/usr/bin/env python3
"""Creates the boilerplate Next.js shell for a fixture variant. Usage: scaffold.py <fixture-dir> [vulnerable secure]"""
import json, pathlib, sys

SHELL = {
  "tsconfig.json": json.dumps({
    "compilerOptions": {"target": "ES2022", "lib": ["dom", "dom.iterable", "esnext"], "strict": True, "noEmit": True,
      "module": "esnext", "moduleResolution": "bundler", "jsx": "preserve", "isolatedModules": True, "skipLibCheck": True,
      "plugins": [{"name": "next"}], "paths": {"@/*": ["./*"]}},
    "include": ["next-env.d.ts", "**/*.ts", "**/*.tsx"], "exclude": ["node_modules"]}, indent=2) + "\n",
  "next.config.ts": 'import type { NextConfig } from "next";\n\nconst nextConfig: NextConfig = {};\n\nexport default nextConfig;\n',
  ".gitignore": "node_modules/\n.next/\n.env\n.env.local\nnext-env.d.ts\n",
  ".env.example": "NEXT_PUBLIC_SUPABASE_URL=http://127.0.0.1:54321\nNEXT_PUBLIC_SUPABASE_ANON_KEY=replace-with-local-anon-key\nSUPABASE_SERVICE_ROLE_KEY=replace-with-local-service-role-key\n",
  "app/layout.tsx": 'import type { ReactNode } from "react";\n\nexport default function RootLayout({ children }: { children: ReactNode }) {\n  return (\n    <html lang="en">\n      <body>{children}</body>\n    </html>\n  );\n}\n',
  "app/page.tsx": 'export default function Home() {\n  return <main>Audit AI fixture app.</main>;\n}\n',
}

def scaffold(fixture: pathlib.Path, variant: str) -> None:
  root = fixture / variant
  root.mkdir(parents=True, exist_ok=True)
  pkg = root / "package.json"
  if not pkg.exists():
    pkg.write_text(json.dumps({
      "name": f"fixture-{fixture.name.split('-')[0]}-{variant}", "version": "0.0.0", "private": True,
      "scripts": {"dev": "next dev -p 3000", "build": "next build", "start": "next start -p 3000"},
      "dependencies": {"@supabase/ssr": "^0.7.0", "@supabase/supabase-js": "^2.57.0", "next": "^15.5.0", "react": "^19.1.0", "react-dom": "^19.1.0"},
      "devDependencies": {"@types/node": "^22.15.0", "@types/react": "^19.1.0", "typescript": "^5.8.0"}}, indent=2) + "\n")
  for rel, text in SHELL.items():
    f = root / rel
    if not f.exists():
      f.parent.mkdir(parents=True, exist_ok=True)
      f.write_text(text)

if __name__ == "__main__":
  fixture = pathlib.Path(sys.argv[1])
  for v in (sys.argv[2:] or ["vulnerable", "secure"]):
    scaffold(fixture, v)
  print("scaffolded", fixture.name)
