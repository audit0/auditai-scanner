# Demo for the README. Regenerate from the repository root with `scripts/demo-gif.sh`
# (vhs captures the frames, ffmpeg assembles the GIF; vhs 0.12's built-in GIF step fails silently with ffmpeg 9).
Output demo-frames.png

Set Shell "bash"
Set FontSize 13
Set FontFamily "Menlo"
Set Width 1100
Set Height 540
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 40ms

# Env must come after every Set: vhs ignores Set directives that follow other commands.
Env NPM_CONFIG_LOGLEVEL "error"

Type "npx auditai-scan evals/fixtures/001-cross-tenant-invoice-read/vulnerable --migrations evals/fixtures/001-cross-tenant-invoice-read/supabase"
Sleep 600ms
Enter
Sleep 7s
