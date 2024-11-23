Main components:
1. Dashboard
   1. Add/remove blacklisted ips
   2. List ongoing attacks.
2. Scanner
   1. Scan local network for attacks
3. Attacker
   1. Send deauth packets to devices that are blacklisted.



Tasks:
1. Convert database such that known devices are stored and the device id is referred everywhere.
2. Make a fallback for finding the local subnet if cannot find it out.
   a. Find out the router ip as well and the mac and store it. (Basically the main AP.)
3. Make the app launch servo, get the url and send it to the frontend.
4. Fix the ui
   a. Make it mobile compatible.
   b. fix the attack logs list.
   c. fix the active_devices list.
   d. fix the add blacklisted_device list.
5. Make the detected attacks such that, it does not spam the database and the attacks are detected as separate with 1 minute gaps.
6. Make the frontend store the link and the cookies.
7. Host the main website on vercel, and have the scanner scan the url. Simple as that. Store the url in the cookies or localstorage, wtv.
8. Keep the active devices list in memory, and every 5 minutes, with the active network scan, store those devices into the sqlite database.
9. In each packet listen, update the last active one, and detect the usage of the packet as well. Basically network monitoring.
10. Make an attacker script for all our attacks.
11. Make a deauth bruteforces script for blacklisted devices. 