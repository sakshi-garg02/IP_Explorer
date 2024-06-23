from flask import Flask, request, render_template, send_file
import pandas as pd
import aiohttp
import asyncio
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
import traceback
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)

API_URL = "http://ip-api.com/json/{}"

def run_async(coroutine):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coroutine)
    finally:
        loop.close()

async def fetch_ip_details(session, ip):
    try:
        async with session.get(API_URL.format(ip)) as response:
            return await response.json()
    except Exception as e:
        app.logger.error(f"Error fetching IP details for {ip}: {str(e)}")
        return {'error': str(e)}

async def ping_ip(ip):
    try:
        proc = await asyncio.create_subprocess_exec('ping', '-c', '1', '-W', '1', ip)
        await proc.wait()
        return proc.returncode == 0
    except Exception as e:
        app.logger.error(f"Error pinging IP {ip}: {str(e)}")
        return False

async def scan_port(ip, port):
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1)
        writer.close()
        await writer.wait_closed()
        app.logger.info(f"Port {port} is open on {ip}")
        return port
    except:
        return None

async def scan_ports_for_ip(ip, port_range):
    open_ports = []
    tasks = [scan_port(ip, port) for port in port_range]
    results = await asyncio.gather(*tasks)
    open_ports = [port for port in results if port is not None]
    app.logger.info(f"Scanned IP: {ip}, Open ports: {open_ports}")
    return open_ports

async def fetch_all_ip_details(ips):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_ip_details(session, ip) for ip in ips]
        return await asyncio.gather(*tasks)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        try:
            action = request.form['action']
            file_type = request.form.get('file_type', request.form.get('file_type_ping'))
            file = request.files.get('file', request.files.get('file_ping'))

            if file:
                if file_type == 'excel':
                    ips = pd.read_excel(file).iloc[:, 0].tolist()
                elif file_type == 'csv':
                    ips = pd.read_csv(file).iloc[:, 0].tolist()
                elif file_type == 'txt':
                    ips = file.read().decode('utf-8').splitlines()

                app.logger.info(f"IPs to be processed: {ips}")

                if action == 'Download Scanned IP List':
                    ip_details = run_async(fetch_all_ip_details(ips))
                    for i, ip in enumerate(ips):
                        ip_details[i]['ip'] = ip
                    ip_details_df = pd.DataFrame(ip_details)
                    excel_file = BytesIO()
                    ip_details_df.to_excel(excel_file, index=False)
                    excel_file.seek(0)
                    return send_file(excel_file, download_name='ip_details.xlsx', as_attachment=True)

                elif action == 'Download Open Port List':
                    ip_ports_dict = {}
                    port_range = range(1, 1024)
                    for ip in ips:
                        open_ports = run_async(scan_ports_for_ip(ip, port_range))
                        ip_ports_dict[ip] = open_ports
                        app.logger.info(f"IP: {ip}, Open ports: {open_ports}")

                    app.logger.info(f"Open ports dictionary: {ip_ports_dict}")

                    ip_ports_list = [{'IP': ip, 'Ports': ', '.join(map(str, ports))} for ip, ports in ip_ports_dict.items()]
                    open_ports_df = pd.DataFrame(ip_ports_list)
                    excel_file = BytesIO()
                    open_ports_df.to_excel(excel_file, index=False)
                    excel_file.seek(0)
                    return send_file(excel_file, download_name='open_ports.xlsx', as_attachment=True)

                elif action in ['Download Reachable IP List', 'Download Unreachable IP List']:
                    pingable_ips = []
                    non_pingable_ips = []
                    for ip in ips:
                        result = run_async(ping_ip(ip))
                        if result:
                            pingable_ips.append(ip)
                        else:
                            non_pingable_ips.append(ip)

                    if action == 'Download Reachable IP List':
                        if pingable_ips:
                            pingable_df = pd.DataFrame(pingable_ips, columns=['IP'])
                            excel_file = BytesIO()
                            pingable_df.to_excel(excel_file, index=False)
                            excel_file.seek(0)
                            return send_file(excel_file, download_name='pingable_ips.xlsx', as_attachment=True)
                        else:
                            return 'No Reachable IPs found. Please try again with a different file.', 404
                    elif action == 'Download Unreachable IP List':
                        if non_pingable_ips:
                            non_pingable_df = pd.DataFrame(non_pingable_ips, columns=['IP'])
                            excel_file = BytesIO()
                            non_pingable_df.to_excel(excel_file, index=False)
                            excel_file.seek(0)
                            return send_file(excel_file, download_name='non_pingable_ips.xlsx', as_attachment=True)
                        else:
                            return 'No Unreachable IPs found. Please try again with a different file.', 404
                        
        except Exception as e:
            app.logger.error(f"Exception in processing request: {str(e)}")
            app.logger.error(traceback.format_exc())
            return 'An error occurred while processing the request. Please check the logs for more details.', 500

    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)