### **Burp Suite Setup Guide**  

#### **Step 1: Open Burp Suite**  
- Launch Burp Suite on your system.  
- Ensure it is running before configuring the proxy.  

#### **Step 2: Use Burp’s Pre-Configured Browser (Easy Method)**  
- Go to **Proxy > Intercept**.  
- Click **Open Browser**.  
- This will open Burp’s pre-configured browser, routing all traffic through Burp automatically.  

#### **Step 3: Configure Firefox to Use Burp Proxy (Manual Method)**  
1. Open **Firefox**.  
2. Go to **Settings > General > Network Settings > Manual Proxy Configuration**.  
3. Set **HTTP Proxy** to **127.0.0.1** and **Port** to **8080** (default Burp port).  
4. Click **OK** to save.  

#### **Step 4: Use FoxyProxy for Quick Proxy Switching (Recommended)**  
1. Install **FoxyProxy** extension from the Firefox Add-ons page.  
2. Click the **FoxyProxy icon** in the Firefox toolbar.  
3. Select **Options > Add New Proxy**.  
4. Enter:  
   - **IP:** 127.0.0.1  
   - **Port:** 8080  
   - **Name:** Burp  
5. Save and enable this profile when using Burp.  

#### **Step 5: Install Burp’s CA Certificate (For HTTPS Traffic)**  
1. Ensure Firefox is set to use Burp as a proxy.  
2. Visit **http://burp** in the browser.  
3. Click **CA Certificate** to download it.  
4. Open Firefox **Settings > Privacy & Security**.  
5. Scroll down and click **View Certificates** under *Certificates*.  
6. Select **Authorities > Import** and choose the downloaded **CA Certificate**.  
7. Enable **"Trust this CA to identify websites"**, then click **OK**.  

#### **Step 6: Start Intercepting Traffic**  
- In Burp Suite, go to **Proxy > Intercept**.  
- Click **Intercept is on** to toggle interception.  
- Navigate to any website in Firefox to see requests in Burp.  

#### **Troubleshooting**  
- If Burp doesn’t capture traffic:  
  - Ensure **Firefox proxy** is set to **127.0.0.1:8080**.  
  - Check **Burp > Proxy > Options** to confirm the listening port.  
  - Restart Firefox and Burp Suite.  
