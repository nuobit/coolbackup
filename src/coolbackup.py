import sys
import re

import os

import datetime
import random
import signal
import shlex
import subprocess
import time
import glob
import psutil

from attrdict import AttrDict
from imapbackup import imapbackup

import yaml

import paramiko


import logging
import logging.handlers
import logging.config

log = logging.getLogger('coolbackup')

PREFIX = 'coolbackup@'

class Bzip2Exception(Exception):
    pass


def signal_term_handler(signal, frame):
    raise SystemError("Killed by another coolbackup. Just one instance is able to run at the same time.")

signal.signal(signal.SIGTERM, signal_term_handler)



class coolssh:
    def __init__(self):
        self.client = None
        self.transport = None


    def connect(self, host, username, port=22, password=None, key_file=None):
        self.host = host
        self.username = username
        self.password = password
        self.key_file = key_file
        key = None
        if key_file is not None:
            key = paramiko.RSAKey.from_private_key_file(key_file)

        self.client = paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if password is not None:
            credentials = dict(password=password)
        else:
            if key is not None:
                credentials = dict(pkey=key)
            else:
                raise Exception("Credentials not defined")

        self.client.connect(host, port=port, username=username, **credentials)
        self.transport = self.client.get_transport()

        #self.transport = paramiko.Transport((self.host, self.port))
        #self.transport.connect(username='almarodrigo', **credentials)
        #print(self.transport.get_security_options())

    def run0(self, cmd, timeout=None):
        channel = self.transport.open_session()
        if timeout is not None:
            channel.settimeout(timeout)
        channel.exec_command(cmd)

        buff_size = 1024
        stdout = b''
        stderr = b''
        while not channel.exit_status_ready():
            time.sleep(0.5)
            if channel.recv_ready():
                stdout += channel.recv(buff_size)

            if channel.recv_stderr_ready():
                stderr += channel.recv_stderr(buff_size)

        exit_status = channel.recv_exit_status()

        # Need to gobble up any remaining output after program terminates...
        while channel.recv_ready():
            stdout += channel.recv(buff_size)

        while channel.recv_stderr_ready():
            stderr += channel.recv_stderr(buff_size)

        channel.close()

        return exit_status, stdout, stderr

    def run(self, cmd, timeout=None):
        stdin, stdout, stderr = self.client.exec_command(cmd, get_pty=True)
        #stdin.channel.shutdown_write()

        out = stdout.read()
        if out == b'':
            out = None
        if out is not None:
            out = out.decode().strip()

        err = stderr.read()
        if err == b'':
            err = None
        if err is not None:
            err = err.decode().strip()

        return out, err

    def get(self, remote_path, local_path):
        sftp = paramiko.SFTPClient.from_transport(self.transport)
        sftp.get(remote_path, local_path)
        sftp.close()

    def put(self, local_path, remote_path):
        sftp = paramiko.SFTPClient.from_transport(self.transport)
        sftp.put(local_path, remote_path)
        sftp.close()



    def close(self):
        if self.transport is not None:
            self.transport.close()
        if self.client is not None:
            self.client.close()


remote_server = coolssh()

class backup_ctrl:
    def __init__(self, file):
        self.file = file
        self.startdate = None

    def start(self):
        pseudo_today = get_pseudo_today()
        self.startdate = pseudo_today.strftime('%Y-%m-%d')
        try:
            with open(self.file, 'r') as f:
                filedate=f.read().strip()
            return filedate == self.startdate
        except FileNotFoundError:
            return False

    def end(self):
        with open(self.file, 'w') as f:
            f.write(self.startdate)


class sshTunnel():
    def __init__(self, host, user, privkey, local_port, remote_port,
                 remote_host='localhost', port=22,
                 sshStrictHostKeyChecking=True, UserKnownHostsFile=False, wait_time = 2):
        # option -oUserKnownHostsFile=/dev/null do not complain if the key changes

        port_forwarding_string = '%s:%s:%s' % (local_port, remote_host, remote_port)

        # search for another ssh processes running with the same local port forwarding
        procs = []
        for proc in psutil.process_iter():
            try:
                pinfo = proc.as_dict(attrs=['pid', 'name'])
                if pinfo['name'] == 'ssh':
                    if port_forwarding_string in proc.cmdline():
                        procs.append(proc)
            except psutil.NoSuchProcess:
                pass

        # kill the other ssh processes
        if procs!=[]:
            log.debug("S'han trobat %i processos ssh amb el port %i obert. matant-los..." % (len(procs), remote_port))
            def on_terminate(proc):
                log.debug("process {} terminated with exit code {}".format(proc, proc.returncode))

            for p in procs:
                p.terminate()
            gone, alive = psutil.wait_procs(procs, timeout=3, callback=on_terminate)
            for p in alive:
                p.kill()

        # open tunnel
        sshTunnelCmd_l = []
        sshTunnelCmd_l.append("ssh -N -L %s -i %s" % (port_forwarding_string, privkey))

        sshTunnelCmd_l.append('-oStrictHostKeyChecking=%s' % ('yes' if sshStrictHostKeyChecking else 'no'))
        if UserKnownHostsFile:
            sshTunnelCmd_l.append('-oUserKnownHostsFile=/dev/null')

        sshTunnelCmd_l.append('-p %i' % port)
        sshTunnelCmd_l.append("%s@%s" % (user, host))

        args = shlex.split(' '.join(sshTunnelCmd_l))
        self.tunnel = subprocess.Popen(args)

        time.sleep(wait_time)  # Give it time

    def kill(self):
        self.tunnel.kill()


def get_pseudo_today():
    dt = datetime.datetime.now(tz=None)
    hour = int(dt.strftime('%H'))
    if hour >= 0 and hour <= 6:  # before 6 is like the night of previous day
        dt = dt - datetime.timedelta(days=1)

    return dt


def check_process():
    procs = []
    for proc in psutil.process_iter():
        pinfo = proc.as_dict(attrs=['pid', 'name'])
        if pinfo['pid'] != os.getpid() and 'python' in pinfo['name']:
            script_path_file = os.path.realpath(__file__)
            if script_path_file in proc.cmdline():
                procs.append(proc)

    # matem els alytres porcesos assh que usen el amteix port
    if procs != []:
        log.debug("There's %i other processes running. Killing them all..." % len(procs))

        def on_terminate(proc):
            log.debug("process {} terminated with exit code {}".format(proc, proc.returncode))

        for p in procs:
            p.terminate()
        time.sleep(10)
        gone, alive = psutil.wait_procs(procs, timeout=3, callback=on_terminate)
        for p in alive:
            p.kill()




def order_by_priority(d):
    MAX_PRIO = 99999
    prio = {}
    for k, v in d.items():
        p = v.get('priority', MAX_PRIO)
        if p < 0:
            p = MAX_PRIO - p
        v['priority'] = p
        prio[k] = AttrDict(v)

    return sorted(prio.items(), key=lambda x: x[1]['priority'])

def local(cmd, to_file=None, shell=False):
    #token = 'gg33@5lDmdpp'
    #cmd = cmd.replace('||', token)
    #subcs = [x.replace(token, '||').strip() for x in cmd.split('|')]
    subcs = [x.strip() for x in cmd.split('|')]
    procantout = None
    for i, cmd1 in enumerate(subcs, 1):
        stdout9 = subprocess.PIPE
        if i==len(subcs):
            if to_file is not None:
                stdout9 = to_file
        proc = subprocess.Popen(cmd1 if shell else shlex.split(cmd1),
                                stdin=procantout,
                                stdout=stdout9,
                                stderr=subprocess.PIPE,
                                shell=shell
                                )
        procantout = proc.stdout
    out, err = proc.communicate(timeout=None)

    if out==b'':
        out = None
    if out is not None:
        out = out.decode().strip()

    if err==b'':
        err = None
    if err is not None:
        err = err.decode().strip()

    return out, err

def run(cmd, typ='remote', to_file=None, shell=False):
    if typ == 'remote':
        out, err = remote_server.run(cmd)
    elif typ == 'local':
        out, err = local(cmd, to_file=to_file, shell=shell)
    else:
        raise Exception("Type %s not defined" % typ)

    if err is not None:
        raise Exception(err)

    return out, err


def pipe2encrypt(cmd, dest_path, dest_filename, encrypt_passwd, typ):
    remote_dest_file = '%s/%s' % (dest_path, dest_filename)
    log.debug("Compressing and encrypting to file '%s'..." % dest_filename)
    cmd = cmd + " | bzip2 -c -z -9 | openssl aes-256-cbc -k '%s' -out '%s'" % (encrypt_passwd, remote_dest_file)
    run(cmd, typ)


def pipe2decrypt(cmd, dest_path_file, encrypt_passwd, typ):
    log.debug("Decrypting and uncompressing to file '%s'..." % dest_path_file)
    cmd = cmd + " | openssl aes-256-cbc -k '%s' -d | bzip2 -c -d" % encrypt_passwd
    with open(dest_path_file, 'wb') as f:
        try:
            run(cmd, typ, to_file=f)
        except Exception as e:
            e_msg = e.args[0]
            if e_msg.startswith('bzip2: Compressed file ends unexpectedly;'):
                raise Bzip2Exception(e_msg)
            raise

def create_local_dir(path):
    path = path.rstrip('/')

    os.makedirs(path, exist_ok=True)

def create_remote_dir(path):
    path = path.rstrip('/')

    run('mkdir -p %s' % path, 'remote')

def clean_dir(backup_base_folder, backup_filenames, typ):
    """ Delete all directory files started by prefix and not in backup_filenames"""
    backup_base_folder = backup_base_folder.rstrip('/')

    arg1 = ' -o '.join(["-name '%s'" % x for x in backup_filenames])
    cmd = "find %s -type f -name '%s*' ! \( %s \)" % (backup_base_folder, PREFIX, arg1)

    out, _ = run(cmd, typ)

    count = 0
    if out is not None:
        count = len(out.split('\n'))
        cmd2 = ' '.join([cmd, '-delete'])
        run(cmd2, typ)

    return count

def file_exists(path_file, typ='remote'):
    cmd = "ls '%s'" % path_file

    try:
        out, _ = run(cmd, typ)
    except:
        return False

    return out == path_file

def compare_files(local_file, remote_file):
    if not file_exists(local_file, typ='local') or not file_exists(remote_file, typ='remote'):
        return False

    log.debug("Generating SHA512 of remote file %s..." % remote_file)
    out, _ = run("sha512sum -b '%s'" % remote_file, 'remote')
    m = re.search(r'^([^*]+\*)', out)
    if m is None:
        raise Exception("Unexpected SHA format: %s" % out)

    log.debug("Verifying SHA512 of local file %s..." % local_file)
    sha512 = '%s%s' % (m.group(1), local_file)
    cmd = "echo '%s' | (LC_ALL=C sha512sum -c --status; echo $?)" % sha512

    out, _ = run(cmd, 'local', shell=True)

    return int(out) == 0


###################################################

def save_directory(remote_source_complex_path, remote_dest_path, local_dest_path, encrypt_passwd, infix=None):
    """
        * Compress and encrypt
        $ tar cP <directory> | bzip2 -c -z -9 | openssl aes-256-cbc -k <password> -out <directory>.tar.bz2.enc

        * Decrypt and decompress
        $ openssl aes-256-cbc -k <password> -d -in <directory>.tar.bz2.enc -out <directory>.tar.bz2
        o
        $ openssl aes-256-cbc -k <password> -d -in <directory>.tar.bz2.enc | bzip2 -c -d > <directory>.tar
        o
        $ openssl aes-256-cbc -k <password> -d -in <directory>.tar.bz2.enc | bzip2 -c -d | tar xv -
    """

    backup_filenames = []
    if isinstance(remote_source_complex_path, dict):
        if len(remote_source_complex_path) != 1:
            raise Exception("Unexpected, the dictionary must be of 1 element %s" % remote_source_complex_path)
        base_dir = list(remote_source_complex_path.keys())[0].rstrip('/')
        source_dir0 = list(remote_source_complex_path.values())[0]
        if source_dir0 != []:
            remote_source_paths = [base_dir + '/' + value_dir for value_dir in source_dir0]
        else:
            remote_source_paths = []
        base_filename0 = base_dir
    elif isinstance(remote_source_complex_path, str):
        base_dir = remote_source_complex_path.rstrip('/')
        remote_source_paths = [base_dir]
        base_filename0 = base_dir
    else:
        raise Exception("Type %s unexpected! %s" % (type(remote_source_complex_path), remote_source_complex_path))

    if remote_source_paths != []:
        base_filename_parts = ['%sfiles' % PREFIX]
        if infix is not None:
            base_filename_parts.append(infix)
        base_filename_parts.append(base_filename0.replace("/", ".").strip('.'))
        base_filename = '%s.tar' % '.'.join(base_filename_parts)
        base_dest_filename = '%s.bz2.enc' % base_filename

        remote_source_files = ' '.join(remote_source_paths)
        cmd = "tar cP --warning=no-file-ignored '%s'" % remote_source_files
        pipe2encrypt(cmd, remote_dest_path, base_dest_filename, encrypt_passwd, 'remote')

        remote_dest_file = '%s/%s' % (remote_dest_path, base_dest_filename)
        local_dest_file = '%s/%s' % (local_dest_path, base_dest_filename)
        log.debug("Downloading file %s..." % base_dest_filename)
        remote_server.get(remote_dest_file, local_dest_file)

        backup_filenames.append(base_dest_filename)

    return backup_filenames


def save_db(host, port, user, passwd, database, engine, remote_dest_path, local_dest_path, encrypt_passwd):
    """
        * Compress and encrypt
        $ PGPASSWORD=<passwd> pg_dump --create --host localhost --port 5432 --username <username> --blobs <database_name> | bzip2 -c -z -9 | openssl aes-256-cbc -k <encrypt_passwd> -out <database_name>.sql.bz2.enc
        $ MYSQL_PWD=<passwd> mysqldump --host=localhost --port=5432 --user=<username> <database_name> | bzip2 -c -z -9 | openssl aes-256-cbc -k <encrypt_passwd> -out <database_name>.sql.bz2.enc

        * Decrypt and decompress
        $ openssl aes-256-cbc -k <password> -d -in <database_name>.sql.bz2.enc | bzip2 -c -d > <database_name>.sql
    """
    backup_filenames = []
    # generem la llista de paths a copiar
    base_filename = '%s%s.%s.sql' % (PREFIX, engine, database)
    base_dest_filename = '%s.bz2.enc' % base_filename

    if engine == 'postgres':
        cmd = 'PGPASSWORD=%s pg_dump --create --host %s --port %i --username %s --blobs --format plain %s' % (passwd, host, port, user, database)
    elif engine == 'mysql':
        cmd = 'MYSQL_PWD=%s mysqldump --host=%s --port=%i --user=%s %s' % (passwd, host, port, user, database)
    else:
        raise Exception("Service engine %s does not exists" % engine)

    pipe2encrypt(cmd, remote_dest_path, base_dest_filename, encrypt_passwd, 'remote')

    remote_dest_file = '%s/%s' % (remote_dest_path, base_dest_filename)
    local_dest_file = '%s/%s' % (local_dest_path, base_dest_filename)
    log.debug("Downloading file %s..." % base_dest_filename)
    remote_server.get(remote_dest_file, local_dest_file)

    backup_filenames.append(base_dest_filename)

    return backup_filenames

def save_git_data(base_path, remote_dest_path, local_dest_path, encrypt_passwd):
    """ Desem les dades dels repostoris git existens per sota la carepta folder per si mes endavant volem restuarat una versio identica

       * Compress and encrypt
       $ cat <directory>.txt | bzip2 -c -z -9 | openssl aes-256-cbc -k pepe -out <directory>.txt.bz2.enc

       * Decrypt and decompress
       $ openssl aes-256-cbc -k <password> -d -in <directory>.txt.bz2.enc | bzip2 -c -d > <directory>.txt
    """
    backup_filenames = []
    log.debug("Searching GIT repositories in %s..." % (base_path,))
    cmd = 'find %s -name ".git"' % base_path
    out, _ = run(cmd, 'remote')

    gits = []
    for git_folder in out.split('\r\n'):
        m = re.match(r'(.+)/\.git$', git_folder)
        if m is None:
            raise Exception('Unexpected: %s' % git_folder)
        gits.append(m.group(1))

    #### Dades git del respository, branch, commit, etc..
    log.debug("Searching GIT repository data %s..." % (base_path,))
    lines = []
    for git_base_folder in gits:
        git_branch, _ = run('cd %s && git rev-parse --abbrev-ref HEAD' % git_base_folder, 'remote')
        git_commit, _ = run('cd %s && git rev-parse HEAD' % git_base_folder, 'remote')
        lines.append("Git folder: '%s', Branch: '%s', Commit: '%s'" % (git_base_folder, git_branch, git_commit))

    base_filename = '%sgit_head.%s.txt' % (PREFIX, base_path.replace("/", ".").strip('.'))
    base_dest_filename = '%s.bz2.enc' % base_filename

    cmd = "echo '%s'" % '\n'.join(lines)
    pipe2encrypt(cmd, remote_dest_path, base_dest_filename, encrypt_passwd, 'remote')

    remote_dest_file = '%s/%s' % (remote_dest_path, base_dest_filename)
    local_dest_file = '%s/%s' % (local_dest_path, base_dest_filename)
    log.debug("Downloading file %s..." % base_dest_filename)
    remote_server.get(remote_dest_file, local_dest_file)

    backup_filenames.append(base_dest_filename)

    log.debug("Searching for local changes in GIT repositories %s..." % (base_path,))
    #### GIT data of local changed files
    for git_base_folder in gits:
        git_mods, _ = run('cd %s; git ls-files --exclude-standard --modified --other' % git_base_folder, 'remote')
        if git_mods is not None:
            backup_filenames += save_directory({git_base_folder: git_mods.split('\r\n')}, remote_dest_path, local_dest_path, encrypt_passwd, infix='git_diff')

    return backup_filenames

def save_python_data(base_path, remote_dest_path, local_dest_path, encrypt_passwd):
    """ Saving installed package data of the selected python virtual environment

       * Compress and encrypt
       $ cat <directory>.txt | bzip2 -c -z -9 | openssl aes-256-cbc -k pepe -out <directory>.txt.bz2.enc

       * Decrypt and decompress
       $ openssl aes-256-cbc -k <password> -d -in <directory>.txt.bz2.enc | bzip2 -c -d > <directory>.txt
    """
    backup_filenames = []

    base_path = base_path.rstrip('/')
    base_filename = '%spython_freeze.%s.txt' % (PREFIX, base_path.replace("/", ".").strip('.'))
    base_dest_filename = '%s.bz2.enc' % base_filename

    cmd = '%s/bin/pip --quiet freeze' % base_path
    pipe2encrypt(cmd, remote_dest_path, base_dest_filename, encrypt_passwd, 'remote')

    remote_dest_file = '%s/%s' % (remote_dest_path, base_dest_filename)
    local_dest_file = '%s/%s' % (local_dest_path, base_dest_filename)
    log.debug("Downloading file %s..." % base_dest_filename)

    remote_server.get(remote_dest_file, local_dest_file)

    backup_filenames.append(base_dest_filename)

    return backup_filenames


def save_imap_ssl(host, remote_source_mailboxes, remote_dest_path, local_dest_path,
                  remote_past_days_dest_paths, local_past_days_dest_paths, encrypt_passwd, tunnel=False):
    """
        * Compress and encrypt
        $ cat <mailbox_filename>.db | bzip2 -c -z -9 | openssl aes-256-cbc -k pepe -out <mailbox_filename>.db.bz2.enc

        * Decrypt and decompress
        $ openssl aes-256-cbc -k <password> -d -in <mailbox_filename>.db.bz2.enc | bzip2 -c -d > <output_file>
    """
    if not tunnel:
        return save_imap_ssl_direct(host, remote_source_mailboxes, remote_dest_path, local_dest_path,
                                    remote_past_days_dest_paths, local_past_days_dest_paths, encrypt_passwd,
                                    port=993, check_from_hostname=True)
    else:
        return save_imap_ssl_tunnel(host, remote_source_mailboxes, remote_dest_path, local_dest_path,
                                    remote_past_days_dest_paths, local_past_days_dest_paths, encrypt_passwd)


def save_imap_ssl_direct(host, remote_source_mailboxes, remote_dest_path, local_dest_path,
                         remote_past_days_dest_paths, local_past_days_dest_paths, encrypt_passwd, port=993, check_from_hostname=True):
    remote_dest_path = remote_dest_path.rstrip('/')
    local_dest_path = local_dest_path.rstrip('/')

    backup_filenames = []

    remote_source_mailboxes1 = []
    for mb in remote_source_mailboxes:
        [x] = dict(mb).items()
        remote_source_mailboxes1.append(x)
    random.shuffle(remote_source_mailboxes1)

    for imap_user, imap_passwd in remote_source_mailboxes1:
        log.debug("Copying mailbox %s..." % imap_user)

        base_filename = '%simap.%s.db' % (PREFIX, imap_user)
        hash_filename = '%s.sha512' % base_filename
        base_dest_filename = '%s.bz2.enc' % base_filename

        local_dest_file = '%s/%s' % (local_dest_path, base_dest_filename)
        remote_dest_file = '%s/%s' % (remote_dest_path, base_dest_filename)

        local_hash_file = '%s/%s' % (local_dest_path, hash_filename)
        remote_hash_file = '%s/%s' % (remote_dest_path, hash_filename)

        local_tmp_file = '%s/%s' % (local_dest_path, base_filename)
        if os.path.exists(local_tmp_file):
            log.debug("A partial copy has been found %s. It will be used to enable incremental copy...." % base_filename)
        else:
            for local_past_day_dest_path, remote_past_days_dest_path in zip(local_past_days_dest_paths, remote_past_days_dest_paths):
                log.debug("Searching for a recent and complete local copy %s. It will be used to enable incremental copy.." % local_past_day_dest_path)
                local_past_day_dest_file = '%s/%s' % (local_past_day_dest_path, base_dest_filename)
                if os.path.exists(local_past_day_dest_file):
                    log.debug("A recent completed local copy has been found %s." % local_past_day_dest_file)
                    if local_past_day_dest_file!=local_dest_file:
                        log.debug("Copying recent local copy to current local copy %s" % base_dest_filename)
                        run("cp '%s' '%s'" % (local_past_day_dest_file, local_dest_file), 'local')
                else:
                    log.debug("Recent completed local copy not found %s." % local_past_day_dest_file)
                    continue

                log.debug("Searching for a recent and complete remote copy %s. It will be used to enable incremental copy..." % remote_past_days_dest_path)
                remote_past_day_dest_hash_file = '%s/%s' % (remote_past_days_dest_path, hash_filename)
                remote_past_day_dest_file = '%s/%s' % (remote_past_days_dest_path, base_dest_filename)
                if file_exists(remote_past_day_dest_hash_file, 'remote') and file_exists(remote_past_day_dest_file, 'remote'):
                    log.debug("A recent completed remote copy has been found %s." % remote_past_day_dest_file)
                    if remote_past_days_dest_path != remote_dest_path:
                        log.debug("Copying recent remote copy to current remote copy %s" % base_dest_filename)
                        run("cp '%s' '%s'" % (remote_past_day_dest_file, remote_dest_file), 'remote')
                        run("cp '%s' '%s'" % (remote_past_day_dest_hash_file, remote_hash_file), 'remote')

                if os.path.exists(local_dest_file):
                    cmd = "cat '%s'" % local_dest_file
                    local_tmp_filename_tmp = '%s~' % base_filename
                    local_tmp_file_tmp = '%s/%s' % (local_dest_path, local_tmp_filename_tmp)
                    try:
                        pipe2decrypt(cmd, local_tmp_file_tmp, encrypt_passwd, 'local')
                        run("mv '%s' '%s'" % (local_tmp_file_tmp, local_tmp_file), 'local')
                        break
                    except Bzip2Exception:
                        log.debug("The local copy found is corrupted. The incremental copy cannot be done %s" % local_past_day_dest_file)
                        run("rm '%s'" % local_tmp_file_tmp, 'local')
                        run("rm '%s'" % local_dest_file, 'local')
                        run("rm -f '%s'" % local_hash_file, 'local')

        imapbackup.backup(host, imap_user, imap_passwd, local_tmp_file, from_ssl=True, from_port=port,
                          check_from_hostname=check_from_hostname)

        sync = True
        if file_exists(remote_dest_file, 'remote') and file_exists(remote_hash_file, 'remote'):
            log.debug("Verifying SHA512 hash between local and remote files %s..." % base_filename)
            cmd_tmpl = "cat '%s'"
            remote_hash, _ = run(cmd_tmpl % remote_hash_file, 'remote')
            local_hash, _ = run(cmd_tmpl % local_hash_file, 'local')
            sync = remote_hash != local_hash

        if sync:
            log.debug("The SHA512 hash are NOT the same o the file does not exists on destination. It's necessary to syncronize the files %s..." % base_dest_filename)
            cmd = "cat '%s'" % local_tmp_file
            pipe2encrypt(cmd, local_dest_path, base_dest_filename, encrypt_passwd, 'local')
            log.debug("Uploading to server %s..." % base_dest_filename)
            remote_server.put(local_dest_file, remote_dest_file)
            remote_server.put(local_hash_file, remote_hash_file)
        else:
            log.debug("The SHA512 hash MATCHES. It's not necessary to compress, encrypt neither uploading anything.")

        log.debug("Removing temporary file %s..." % base_filename)
        run('rm %s' % local_tmp_file, 'local')

        backup_filenames.append(base_dest_filename)
        backup_filenames.append(hash_filename)

    return backup_filenames

def save_imap_ssl_tunnel(host, remote_source_mailboxes, remote_dest_path, local_dest_path,
                         remote_past_days_dest_paths, local_past_days_dest_paths, encrypt_passwd):
    log.debug("Creating SSH tunnel...")
    tun = sshTunnel(remote_server.host, remote_server.username, remote_server.key_file, local_port=10993, remote_port=993,
                    remote_host=host, sshStrictHostKeyChecking=False, wait_time=5)
    try:
        return save_imap_ssl_direct('localhost', remote_source_mailboxes, remote_dest_path, local_dest_path,
                                    remote_past_days_dest_paths, local_past_days_dest_paths, encrypt_passwd, port=10993,
                                    check_from_hostname=False)
    finally:
        log.debug("Destroying tunnel...")
        tun.kill()


def backup_server(config, remote_backup_base_folder, local_backup_base_folder, remote_backup_base_past_days_folders, local_backup_base_past_days_folders):
    backup_filenames = []
    ordered_services = order_by_priority(config.services)
    for service_name, params in ordered_services:
        log.info("Starting copy of %s..." % service_name)
        if params.type == 'imap':
            backup_filenames += save_imap_ssl(params.host, params.mailboxes,
                                              remote_backup_base_folder, local_backup_base_folder,
                                              remote_backup_base_past_days_folders, local_backup_base_past_days_folders,
                                              config.params.encrypt_passwd,
                                              tunnel=params.get('tunnel', False))
        elif params.type == 'db':
            backup_filenames += save_db(params.host, params.port, params.username, params.password, params.database, params.engine,
                                        remote_backup_base_folder, local_backup_base_folder, config.params.encrypt_passwd)
        elif params.type == 'files':
            backup_filenames = []
            for d in params.directories:
                backup_filenames += save_directory(d, remote_backup_base_folder, local_backup_base_folder, config.params.encrypt_passwd)
        elif params.type == 'gitdata':
            backup_filenames += save_git_data(params.path, remote_backup_base_folder, local_backup_base_folder, config.params.encrypt_passwd)
        elif params.type == 'pythondata':
            backup_filenames += save_python_data(params.path, remote_backup_base_folder, local_backup_base_folder, config.params.encrypt_passwd)
        log.info("End of %s database copy." % service_name)

    return backup_filenames


#TODO:
# * Save only the local changes and send it only these to server.
# * Sha512 of files too (imap is already done).
# * LOG identations.
# * Deal with error when encrypt passwords differs.
# * Refactor ssh tunnel using Paramiko.
# * Check ssh cipher params, improve security if it's possible an efficient.
# * Using tee or similar to upload files to server and write to local filesystem if it's possible.
# * Using rsync or similar to copy files.
# * Allow user to choose if the copy is only locl or it leaves a copy in the server too.
# * a lot of refactor and optimizations
def main():
    base_path = sys.argv[1]

    logger_path = '%s/logger.conf' % base_path
    with open(logger_path, 'r') as f:
        logger_conf = yaml.load(f)
    logger_conf['handlers']['file_log']['filename'] = '%s/coolbackup.log' % base_path
    logging.config.dictConfig(logger_conf)

    check_process()

    pseudo_today = get_pseudo_today()
    week_today = (int(pseudo_today.strftime('%w')) - 1) % 7 + 1

    week_past_days = []
    for d in reversed(range(week_today, week_today + 7)):
        week_past_days.append((d - 1) % 7 + 1)

    conf_path = '%s/servers.conf.d' % base_path
    for conf_filename in sorted(os.listdir(conf_path)):
        try:
            conf_file = '%s/%s' % (conf_path, conf_filename)
            with open(conf_file, 'r') as f:
                config = AttrDict(yaml.load(f))

            log.info("--------------- Start of backup %s day %i ------------------" % (config.params.username, week_today))
            if config.params.get('enabled', True):
                local_backup_folder = '%s/%i' % (config.params.local_dest_path, week_today)
                create_local_dir(local_backup_folder)

                bc = backup_ctrl('%s/coolbackup.dat' % local_backup_folder)
                already_done = bc.start()
                if not already_done:
                    remote_server.connect(config.params.server, config.params.username, key_file=config.params.key_file)

                    remote_backup_folder = '%s/%i' % (config.params.remote_dest_path, week_today)
                    create_remote_dir(remote_backup_folder)

                    remote_backup_past_days_folders = ['%s/%i' % (config.params.remote_dest_path, week_past_day) for week_past_day in week_past_days]
                    local_backup_past_days_folders = ['%s/%i' % (config.params.local_dest_path, week_past_day) for week_past_day in week_past_days]
                    backup_filenames = backup_server(config, remote_backup_folder, local_backup_folder,
                                                     remote_backup_past_days_folders, local_backup_past_days_folders)

                    log.info("Cleaning obsolete files...")
                    clean_dir(local_backup_folder, backup_filenames, 'local')
                    clean_dir(remote_backup_folder, backup_filenames, 'remote')

                    bc.end()
                else:
                    log.info("Today copy is already done.")
            else:
                log.info("Copy disabled.")

            log.info("--------------- End of backup %s dia %i <OK> ----------------" % (config.params.username, week_today))
        except (SystemError, KeyboardInterrupt) as e:
            log.debug("Sending error e-mail...")
            log.exception("Error backing up '%s'" % config.params.username)
            log.debug("E-mail sent.")
            log.info("------------------- End of backup day %i <ERROR> ----------------------" % week_today)
            raise
        except:
            log.debug("Sending error e-mail...")
            log.exception("Error backing up '%s'" % config.params.username)
            log.debug("E-mail sent.")
            log.info("------------------- End of backup day %i <ERROR> ----------------------" % week_today)
        finally:
            remote_server.close()
            logging.shutdown()


if __name__ == "__main__":
    main()