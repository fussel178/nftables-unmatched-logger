#!/usr/bin/env python3

import sqlite3
from systemd import daemon
import socket
import sys
import os
import re
import json
import signal
from json import JSONDecodeError

database_path = "/var/lib/nftables-unmatched-logger/main.sqlite"
unix_socket_path = "/run/nftables-unmatched-logger/ulog.sock"
nft_log_prefix = "nft_in_unmtch"

db_table_services = """ CREATE TABLE IF NOT EXISTS services (
  id integer PRIMARY KEY,
  first_seen text NOT NULL,
  last_seen text NOT NULL,
  port integer NOT NULL,
  proto text NOT NULL,
  name text
)
"""

db_table_addresses = """ CREATE TABLE IF NOT EXISTS addresses (
  id integer PRIMARY KEY,
  first_seen text NOT NULL,
  last_seen text NOT NULL,
  ip_address text NOT NULL,
  whois_record text
)
"""

db_table_calls = """ CREATE TABLE IF NOT EXISTS calls (
  id integer PRIMARY KEY,
  address_id integer NOT NULL,
  service_id integer NOT NULL,
  count integer NOT NULL,
  FOREIGN KEY (address_id) REFERENCES addresses(id) ON UPDATE CASCADE ON DELETE CASCADE,
  FOREIGN KEY (service_id) REFERENCES services(id) ON UPDATE CASCADE ON DELETE CASCADE
)
"""

def create_table(db, table_spec) -> None:
  cursor = db.cursor()
  cursor.execute(table_spec)

def alter_table(db, alter_spec) -> None:
  cursor = db.cursor()
  cursor.execute(alter_spec)

def upsert_service(db, port: int, proto: str) -> None:
  cursor = db.cursor()
  cursor.execute("SELECT id FROM services WHERE port = ? AND proto = ?", (port, proto))
  service = cursor.fetchone()

  if service != None:
    cursor = db.cursor()
    cursor.execute("UPDATE services SET last_seen = datetime('now') WHERE id = ?", service)
    return service[0]

  # service does not exist yet -> create new entry
  cursor = db.cursor()
  service_name = None
  try:
    service_name = socket.getservbyport(port, proto)
  except OSError:
    pass
  
  cursor.execute("INSERT INTO services(port, proto, name, first_seen, last_seen) VALUES(?, ?, ?, datetime('now'), datetime('now'))", (port, proto, service_name))
  return cursor.lastrowid

def upsert_address(db, ip_address: str) -> int:
  cursor = db.cursor()
  cursor.execute("SELECT id FROM addresses WHERE ip_address = ?", (ip_address,))
  address = cursor.fetchone()

  if address != None:
    cursor = db.cursor()
    cursor.execute("UPDATE addresses SET last_seen = datetime('now') WHERE id = ?", address)
    return address[0]

  # address does not exist yet -> create new entry
  cursor = db.cursor()
  cursor.execute("INSERT INTO addresses(first_seen, last_seen, ip_address) VALUES(datetime('now'), datetime('now'), ?)", (ip_address,))
  return cursor.lastrowid

def increment_call(db, address_id: int, service_id: int):
  cursor = db.cursor()
  cursor.execute("SELECT id,count FROM calls WHERE address_id = ? AND service_id = ?", (address_id, service_id))
  call = cursor.fetchone()

  if call != None:
    cursor = db.cursor()
    cursor.execute("UPDATE calls SET count = ? WHERE id = ?", (call[1] + 1, call[0]))
  else:
    cursor = db.cursor()
    cursor.execute("INSERT INTO calls(address_id, service_id, count) VALUES(?, ?, ?)", (address_id, service_id, 1))

def register_exit_handler(handler):
  for sig in (signal.SIGABRT, signal.SIGILL, signal.SIGINT, signal.SIGSEGV, signal.SIGTERM):
    signal.signal(sig, handler)

def main():
  print("Start process")
  db = None
  server = None

  print("Open SQLite database")
  sys.stdout.flush()
  db = sqlite3.connect(database_path)

  def close_db(signum, frame):
    if db:
      print("Close SQLite database")
      sys.stdout.flush()
      db.close()
  register_exit_handler(close_db)

  print("Create tables")
  sys.stdout.flush()
  create_table(db, db_table_services)
  create_table(db, db_table_addresses)
  create_table(db, db_table_calls)

  print("Open UNIX socket: " + unix_socket_path)
  sys.stdout.flush()
  try:
    os.unlink(unix_socket_path)
  except OSError:
    if os.path.exists(unix_socket_path):
      raise
  
  server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  server.bind(unix_socket_path)
  server.listen(1)

  # register first handler
  def close_server(signum, frame):
    if server:
      print("Close socket")
      sys.stdout.flush()
      server.close()
    close_db(signum, frame)
  register_exit_handler(close_server)

  while True:
    print("Waiting for ulog to connect...")
    sys.stdout.flush()
    daemon.notify("READY=1")
    daemon.notify("STATUS=Waiting for ulog daemon to connect…")
    connection, _ = server.accept()

    def close_connection(signum, frame):
      if connection:
        print("Close ulog connection")
        sys.stdout.flush()
        connection.close()
      close_server(signum, frame)
    register_exit_handler(close_connection)

    print("Ulog is connected. Interpreting data...")
    sys.stdout.flush()
    daemon.notify("STATUS=Ulog is connected. Interpreting data...")
    prepared = ""
    while True:
      raw = connection.recv(4096)
      prepared += raw.decode("ascii")
      parts = re.split(r'(?<=})\n(?={)', prepared)
      prepared = ""
      for part in parts:
        try:
          # netfilter packet
          decoded = json.loads(part)

          # skip wrong prefixed packet
          if decoded["oob.prefix"] != nft_log_prefix:
            continue

          src_ip = decoded["src_ip"]
          ip_protocol = decoded["ip.protocol"]
          dest_port = decoded["dest_port"]

          protocol_name = None
          if ip_protocol == 6:
            protocol_name = "tcp"
          elif ip_protocol == 17:
            protocol_name = "udp"
          else:
            # not a TCP or UDP packet -> ignoring (for now)
            continue

          service_id = upsert_service(db, dest_port, protocol_name)
          address_id = upsert_address(db, src_ip)
          increment_call(db, address_id, service_id)
          db.commit()

        except JSONDecodeError:
          # incomplete JSON object -> store for next decoding round
          prepared += part
        except sqlite3.Error as e:
          print(e)
          print("Continue with next packet...")
          sys.stdout.flush()
        except Exception as e:
          print("Unhandled packet: {}".format(part))
          sys.stdout.flush()
          raise e

if __name__ == '__main__':
  main()
