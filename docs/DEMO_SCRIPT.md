# Sentinel: Demo video script

A two-minute screen recording for the CV and LinkedIn. Read the lines in your own voice; they are a guide, and it is fine to change a word. Aim for calm and clear, not fast.

## The script

| Time | On screen | What to say |
| --- | --- | --- |
| 0:00–0:15 | The **Dashboard**, empty | "I'm Mohamed Hassan, and this is Sentinel: an AI-assisted SOC triage tool I built to practise the analyst workflow without a home lab. Every log you will see is simulated, so nothing real is attacked." |
| 0:15–0:35 | Press **Run scenario** with **Full attack chain** selected. Let the numbers update. | "I'll run the full attack chain. The simulator writes a phishing email, a hidden PowerShell download, a new administrator account, and two gigabytes leaving the network, all hidden among normal office activity. The rules raised nine alerts, and the ATT&CK strip shows how far the attack got." |
| 0:35–1:00 | Open **Alerts**, then the alert **PowerShell Started With An Encoded Command** | "This is the alert queue. I'll open this one. My detection rule is written in Sigma, the open format SOC teams share, and it caught PowerShell being started with an encoded command. It maps to ATT&CK technique T1059.001, and this is the exact log line that set it off." |
| 1:00–1:20 | Scroll to the **AI triage** card. Press **Accept suggestion**. | "The AI explains the alert in plain English, suggests a severity and lists next steps. It is only a suggestion: I accept it or edit it, and I stay accountable. The phishing email even hides an instruction telling the AI to rate it Low. Sentinel treats that as evidence, not as an order." |
| 1:20–1:40 | Open **Incidents**, then **Incident #1**. Scroll slowly down the timeline. | "One at a time these are nine small alerts. Correlation groups alerts that share a host or a user within thirty minutes, so the attack reads as one story: from Initial Access to Exfiltration in under half an hour." |
| 1:40–1:55 | Scroll back up. Press **Download report** and open the PDF. | "One click gives a report a manager could read: an executive summary, the timeline, the indicators of compromise, and the containment and recovery steps." |
| 1:55–2:00 | The GitHub page | "The code is linked below, and it runs with one Docker command. Thanks for watching." |

That is about 250 words, which is two minutes at an unhurried pace.

## Before you record

1. Start from an empty Sentinel, so the dashboard shows zeros. In a terminal in the project folder, run `docker compose down -v`, then `docker compose up`. Open http://localhost:8000.
2. Make the browser window about 1280 by 800, at 100% zoom, with no other tabs and the bookmarks bar hidden (Ctrl+Shift+B).
3. Close anything that might pop up a notification.
4. Do one silent practice run of the clicks, then repeat step 1 so the store is empty again.

## How to record on Windows

Windows has a recorder built in, called Xbox Game Bar.

1. Click on the browser window so it is the active one.
2. Press **Windows + Alt + R**. Recording starts, and a small timer appears in a corner.
3. To record your voice too, press **Windows + Alt + M** once the timer is showing. The microphone icon on the timer should not be crossed out.
4. Go through the script.
5. Press **Windows + Alt + R** again to stop.
6. The video is saved as an MP4 file in your **Videos** folder, inside **Captures**.

If the shortcut does nothing, open **Settings**, choose **Gaming**, then **Xbox Game Bar**, and switch it on.

## After recording

- Watch it once with the sound on. If you stumbled, record again: a second take is usually better.
- Upload the MP4 straight to the LinkedIn post (see [LINKEDIN_POST.md](LINKEDIN_POST.md)).
- There is no hosted demo, so for most people the video is the only way they will see Sentinel run. It is worth getting right.
