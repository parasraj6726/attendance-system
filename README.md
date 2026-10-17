# Duty Attendance

Login-based attendance for Bhopal, RKMP, Nishatpura and DRM Office.

- **Admin** builds the roster (name, employee ID, PIN, section, weekly rest day), gives rest or leave for any date, fixes forgotten check-outs, and downloads one monthly CSV for salary.
- **Employees** sign in with their own ID and PIN, and can only check in and out for themselves. Times come from the server clock, not the phone.

## Run it

    npm install
    npm start

First run prints the admin ID and PIN in the terminal. Open http://localhost:3000, sign in, then use the Staff tab to add people and change your PIN.
To choose the admin login yourself, set `ADMIN_ID` and `ADMIN_PIN` before the first run.

## Settings (environment variables)

| Name | Default | Meaning |
|---|---|---|
| PORT | 3000 | Port to listen on |
| DB_PATH | ./data.db | Where the database file lives |
| TZ_NAME | Asia/Kolkata | Time zone used for dates |
| TZ_OFFSET | +05:30 | Used when the admin types times by hand |
| ADMIN_ID / ADMIN_PIN | admin / random | Only used when the database is empty |

## Put it online

It needs somewhere that runs Node 18 or newer and keeps the `data.db` file between restarts.

1. **Office PC or a small VPS:** run `npm start` (use `pm2` to keep it running). Staff on the office network open `http://<that-pc-ip>:3000`.
2. **Render or Railway:** create a Web Service from this folder, build command `npm install`, start command `npm start`, and attach a persistent disk or volume. Set `DB_PATH` to a path on that disk. Without a persistent disk the data is wiped on every restart.

Use HTTPS when it is on the public internet (Render and Railway provide it).

## Back up

Copy `data.db` regularly. That one file holds everything.

## Rules built in

- One attendance record per person per day. Night duty works: check-out closes the open duty even after midnight.
- Past days with no record count as Absent. Today and future days are left blank. Download the file after the month ends.
- People added mid-month only count from their start date. Removed people stay in the reports for the days they worked.
- Five wrong PIN tries lock that ID and device for 10 minutes.
