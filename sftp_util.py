#! /usr/bin/python
# -*- coding:utf-8 -*-

import traceback
import paramiko
import socket
import errno
import stat
import sys
import re
import os


class SFTP(object):

    authfailed    = 'AuthFailed'
    passrequired  = 'PassRequired'
    timeout       = 'Timeout'
    acldenied     = 'AclDenid'
    notsuch       = 'NotSuch'
    unknow        = 'Unknow'
    alreadyexists = 'AlreadyExists'
    isdirectory   = 'IsDirectory'

    def assert_connect(function_override):
        def assert_wraps(self, *args, **kwargs):
            assert self.is_connect is True, 'You use function connect()'
            return function_override(self, *args, **kwargs)
        return assert_wraps

    def assure_function(function_override):
        def assure_wraps(self, *args, **kwargs):
            try:
                return True, '', '', function_override(self, *args, **kwargs)
            except Exception as error:
                errortrace = self._get_exception()
                errorid    = self.unknow
                if isinstance(error, IOError):
                    if error.args:
                        errno_id= error.args[0]
                        if errno_id == errno.ENOENT:
                            errorid = self.notsuch
                        elif errno_id == errno.EACCES:
                            errorid = self.acldenied
                        elif errno_id == errno.EISDIR:
                            errorid = self.isdirectory
                elif isinstance(error, socket.timeout):
                    errorid = self.timeout
                elif isinstance(error, paramiko.PasswordRequiredException):
                    errorid = self.passrequired
                elif isinstance(error, paramiko.AuthenticationException):
                    errorid = self.authfailed

                return False, errorid, errortrace, error

        return assure_wraps

    def __init__(self, **kwargs):
        ''''''
        self.is_connect      = False

        if not  kwargs.get('max_bufsize'):
            self.max_bufsize = 15 << 21 # 30Mb
        else:
            self.max_bufsize = kwargs['max_bufsize']

    @assert_connect
    def __enter__(self):
        ''''''
        return self

    def __exit__(self, exc_type, exc_val, tb):
        self.close()

    def close(self):
        assert self.is_connect is True, 'Use function connect before close'

        try:
            self.conn_sftp.close()
        except:
            pass

        try:
            self.conn_ssh.close()
        except:
            pass

        self.is_connect = False

    ###################################################################
    def connect(self, host, user, password, port=22, timeout=20, add_policy=True, **kwargs):
        
        server = 'servidor'
        if kwargs.pop('show_credentials', False):
            server = 'servidor({})'.format(host)

        credentials = ''
        if kwargs.pop('show_url', False):
            credentials = ', usuario: "{}" clave: "{}"'.format(user, password)

        success, errorid, errortrace, _ = self._connect(host, user, password, port, timeout, add_policy, **kwargs)

        message = ''
        if success:
            self.is_connect = True
        else:
            if errorid == self.authfailed:
                message = 'No se ha podido conectar al {} con las credenciales proporcionadas{}'.format(server, credentials)

            elif errorid == self.passrequired:
                message = 'La clave es requerida para conexión con el {}{}'.format(server, credentials)

            elif errorid == self.timeout:
                message = 'El tiempo({}) de espera para el {} se ha terminado'.format(timeout, server)

            else:
                message = 'Error de conexión con el {}'.format(server)

        return success, message, errortrace

    @assure_function
    def _connect(self, host, user, password, port, timeout, add_policy, **kwargs):
        
        assert not self.is_connect, 'Use function close()'

        self.conn_ssh = paramiko.SSHClient()
        
        if add_policy:
            self.conn_ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        self.conn_ssh.connect(host, username=user, password=password, port=port, timeout=timeout, **kwargs)

        self.conn_sftp  = self.conn_ssh.open_sftp()

        self.is_connect = True

    ###################################################################
    def get(self, filepath_remote, filepath_local, confirm=True, **kwargs):
        
        filepath_local  = self.assert_path(filepath_local, 'filepath_local')
        filepath_remote = self.assert_path(filepath_remote, 'filepath_remote')

        dirpath_local = os.path.split(filepath_local)[0]

        success, message, error = self.hasaccess(dirpath_local, os.W_OK, dir_or_file=True)

        if not success:
            return success, message, error

        success, errorid, errortrace, result_or_error = self._get(filepath_remote, filepath_local, **kwargs)
        
        if not success:
            return success, 'Error al obtener archivo del servidor remoto', errortrace

        elif not confirm:
            return success, '', ''

        if not os.path.exists(filepath_local):
            return False, 'No se pudo crear el archivo local', ''

        elif os.path.getsize(filepath_local) == 0:
            return False, 'El volumen del archivo local es: 0', ''

        return success, '', ''

    def get_to_buffer(self, filepath_remote, chunksize=1 << 15, **kwargs):

        filepath_remote = self.assert_path(filepath_remote)

        if chunksize > self.max_bufsize:
            return False, 'El tamaño({}) de buffer por lote supera lo permidito: {}'.format(chunksize, self.max_bufsize),''

        success, message, result_or_error = self.stat(filepath_remote)

        if not success:
            return success, message, result_or_error

        if result_or_error.st_size > self.max_bufsize:
            return False, 'El tamaño({}) del archivo en el servidor supera el tamaño({}) de buffer permitido'.format(result_or_error.st_size, self.max_bufsize), ''

        if chunksize > paramiko.SFTPFile.MAX_REQUEST_SIZE:
            return (
                False,
                'El tamaño({}) de buffer supera al tamaño({}) por petición que se le puede realizar al archivo del servidor'.format(chunksize, result_or_error.MAX_REQUEST_SIZE),
                ''
            )

        success, errorid, errortrace, result = self._get_to_buffer(filepath_remote, chunksize, **kwargs)
        message = ''
        if not success:
            message = self.interpret_error(errorid, filepath_remote)
        
        return success, message, result if success else errortrace

    def put(self, filepath_local, filepath_remote, **kwargs):
        
        filepath_local  = self.assert_path(filepath_local, 'filepath_local')
        filepath_remote = self.assert_path(filepath_remote, 'filepath_remote')

        success, message, errortrace = self.hasaccess(filepath_local, os.R_OK, False)
        if not success:
            return success, message, errortrace

        success, errorid, errortrace, result = self._put(filepath_local, filepath_remote, **kwargs)

        message = ''
        if not success:
            message = 'Error al enviar el archivo al servidor remoto' ##Por aqui poner más errores

        return success, message, result if success else errortrace

    def put_from_str(self, objstr, full_filepath, confirm=True, chunksize=1 << 15, **kwargs):
        
        assert isinstance(objstr, basestring), 'objstr is not basestring'

        full_filepath = self.assert_path(full_filepath, 'full_filepath')

        filepath, filename = os.path.split(full_filepath)
        assert filename, 'filename is required for put file'
        
        if chunksize > paramiko.SFTPFile.MAX_REQUEST_SIZE:
            return (
                False,
                'El tamaño({}) del buffer supera al tamaño({}) por petición que se le puede realizar al archivo del servidor'.format(chunksize, paramiko.SFTPFile.MAX_REQUEST_SIZE),
                ''
            )

        success, message, errortrace = self.mkdir(filepath)
        if not success:
            return success, message, errortrace

        success, _, errortrace, _ = self._put_from_str(objstr, full_filepath, chunksize, **kwargs)

        if not success:
            return success, 'Error al subir el archivo: {} en el servidor'.format(full_filepath), errortrace

        elif not confirm:
            return success, '', ''

        success, errorid, errortrace, error_or_result = self._stat(filepath)

        if not success:
            return success, 'El archivo pudo no haber subido correctamente, no se puede obtener información del mismo', error_or_result

        message = ''
        if error_or_result.st_size <= 0:
            message = 'El volumen del archivo: "{}" en el servidor es menor o igual que 0'.format(filename)
            success = False

        return success, message, errortrace

    def rmfile(self, filepath_remote):
        filepath_remote = self.assert_path(filepath_remote)

        success, errorid, errortrace, _ = self._unlink(filepath_remote)

        message = ''
        if not success:
            message = self.interpret_error(errorid, filepath_remote)

        return success, message, errortrace

    def mkdir(self, dirpath, mode=None):
        '''
        Se realizo el chmod despues del crear la carpeta ya que en algunos sistemas ignoran
        el argumento y crean la carpeta con os.unmask en mis pruebas le mandaba 0777 y las creaba con 0755:
        '''

        assert isinstance(dirpath, basestring), 'dirpath argument is not basestring'
        
        setmode = mode is not None
        if setmode:
            assert isinstance(mode, int), 'mode argument is not int'
            if not(mode >= 0001 and mode <= 0777):
                return (
                    False,
                    'El permiso para la ruta remota "{}" no es valido'.format(dirpath),
                    'Your permission int({}) is not valid, range avalible 1-511(int) and 0001-0777(oct)'.format(mode)
                )

        success, errorid, errortrace, result_or_error = self._stat(dirpath)
        if success:
            if result_or_error and isinstance(result_or_error, paramiko.SFTPAttributes):
                message = 'El directorio ya existe'
                if setmode:
                    success, _, errortrace, _ = self._chmod(dirpath, mode)
                    if not success:
                        message += ', se intentaron cambiar los permisos sin éxito'
                    else:
                        message += ', se cambiaron los permisos correctamente'

                return True, message, errortrace
        else:
            if errorid != self.notsuch:
                return success, self.interpret_error(errorid, dirpath), errortrace

        success, errorid, errortrace, _ = self._mkdir(dirpath)
        message = ''
        if not success:
            message = self.interpret_error(errorid, dirpath)

        elif mode is not None:
            success_chmod, _, errortrace ,_ = self._chmod(dirpath, mode)
            if not success_chmod:
                message = 'Se creo la carpeta pero los permisos proporcionados no pudieron ser establecidos'

        return success, message, errortrace

    def rmdir(self, dirpath):
        assert isinstance(dirpath, basestring), 'dirpath argument is not basestring'

        success, errorid, errortrace, _ = self._rmdir(dirpath)

        message = ''
        if not success:
            message = self.interpret_error(errorid, dirpath)

        return success, message, errortrace

    def stat(self, dirpath):
            
        dirpath = self.assert_path(dirpath, 'dirpath')

        success, errorid, errortrace, result = self._stat(dirpath)

        message = ''
        if not success:
            message = self.interpret_error(errorid, dirpath)

        return success, message, result if success else errortrace

    def listdir(self, dirpath, matchfile=None, matchdir=None, followlinks=False):

        assert isinstance(dirpath, basestring), 'dirpath argument is not basestring'

        success, errorid, errortrace, result_or_error = self._listdir(dirpath)

        if not success:
            return success, self.interpret_error(errorid, dirpath), errortrace

        path_dirs, path_files = [],[]

        for eachfile in result_or_error:

            filename = eachfile.filename.encode('utf-8') if isinstance(eachfile.filename, unicode) else eachfile.filename

            if not followlinks and stat.S_ISLNK(eachfile.st_mode):
                continue

            if stat.S_ISDIR(eachfile.st_mode):
                if matchdir and not re.search(matchdir, filename):
                    continue
                path_dirs.append(filename)

            elif stat.S_ISREG(eachfile.st_mode):
                if matchfile and not re.search(matchfile, filename):
                    continue
                path_files.append(filename)

        return success,'', (path_dirs, path_files)

    def rename(self, origin_path, destiny_path, replace=False):

        origin_path  = self.assert_path(origin_path, 'origin_path')
        destiny_path = self.assert_path(destiny_path, 'destiny_path')

        success, errorid, errortrace, _ = self._rename(origin_path, destiny_path)
        print 'errorid'
        print errorid
        print 'errorid'
        if not success and errorid == self.unknow and replace:
            self._unlink(destiny_path)
            success, errorid, errortrace, _ = self._rename(origin_path, destiny_path)
        
        message = ''
        if not success:
            message = 'Ha ocurrido un error al mover el archivo: "{}" a "{}"'.format(origin_path, destiny_path)
        
        return success, message, errortrace

    def chmod(self, filepath_remote, mode):
        filepath_remote = self.assert_path(filepath_remote)

        assert isinstance(mode, int), 'mode argument is not int'

        if not(mode >= 0001 and mode <= 0777):
            return False, 'El permiso: {} para el archivo remoto no esta en el rango octal 0001 - 0777'.format(oct(mode))

        success, errorid, errortrace, _ = self._chmod(filepath_remote, mode)

        message = ''
        if not success:
            message = self.interpret_error(errorid, filepath_remote)

        return success, message, errortrace

    @assert_connect
    def walk(self, rootpath, matchfile=None, followlinks=False):
        
        success, errortrace, result_or_error = self.listdir(rootpath, matchfile=matchfile, followlinks=followlinks)

        path_dirs, path_files = result_or_error if success else ([],[])

        subpath_dirs = [os.path.join(rootpath, eachpath) for eachpath in path_dirs]

        yield success, errortrace,(rootpath, path_dirs, path_files)

        for each_subdir in subpath_dirs:
            for eachresult in self.walk(each_subdir, matchfile=matchfile, followlinks=followlinks):
                yield eachresult

    ###################################################################
    
    @assure_function
    @assert_connect
    def _get(self, filepath_remote, filepath_local, **kwargs):
        return self.conn_sftp.get(filepath_remote, filepath_local, **kwargs)

    @assure_function
    @assert_connect
    def _get_to_buffer(self, filepath_remote, chunksize, callback=None):
        buffer_stream = ''
        with self.conn_sftp.open(filepath_remote, mode='r') as remote_file:
            while 1:
                data_content = remote_file.read(chunksize)
                if not data_content:
                    break
                buffer_stream += data_content
                if callback:
                    callback(data_content)
        return buffer_stream

    @assure_function
    @assert_connect
    def _put(self, filepath_local, filepath_remote, **kwargs):
        return self.conn_sftp.put(filepath_local, filepath_remote, **kwargs)

    @assure_function
    @assert_connect
    def _put_from_str(self, objstr, filepath, chunksize, callback=None):
        with self.conn_sftp.open(filepath, 'w') as remote_file:
            start = ends  = 0
            while 1:
                start = ends
                ends += chunksize
                data_write = objstr[start:ends]
                if not data_write:
                    break
                remote_file.write(data_write)
                if callback:
                    callback(start, ends, data_write)

    @assure_function
    @assert_connect
    def _rename(self, origin_path, destiny_path):
        self.conn_sftp.rename(origin_path, destiny_path)

    @assure_function
    @assert_connect
    def _listdir(self, dirpath):
        return self.conn_sftp.listdir_attr(dirpath)

    @assure_function
    @assert_connect
    def _stat(self, dirpath):
        return self.conn_sftp.stat(dirpath)

    @assure_function
    @assert_connect
    def _mkdir(self, dirpath):
        os.umask(0)
        self.conn_sftp.mkdir(dirpath)

    @assure_function
    @assert_connect
    def _unlink(self, filepath_remote):
        return self.conn_sftp.unlink(filepath_remote)

    @assure_function
    @assert_connect
    def _chmod(self, filepath_remote, mode):
        return self.conn_sftp.chmod(filepath_remote, mode)

    ###################################################################
    @staticmethod
    def assert_path(argpath, argname='filepath_remote'):

        assert isinstance(argpath, (basestring,tuple)), '{} argument is not basestring or tuple'.format(argname)

        if isinstance(argpath, tuple):
            result = len(argpath) == 2 and all([isinstance(arg, basestring) for arg in argpath])
            assert result, '{} argument tuple, length is not 2 or any value is not basestring'.format(argname)
            argpath = os.path.join(*argpath)

        return argpath

    @staticmethod
    def hasaccess(routepath, permissions, dir_or_file=True):
        if not os.path.exists(routepath):
            return False, 'La ruta local no existe', 'Path do not exists'

        if dir_or_file and not os.path.isdir(routepath):
            return False, 'La ruta local de la carpeta es un archivo', 'Path dir local is a file'

        if not dir_or_file and not os.path.isfile(routepath):
            return False, 'La ruta del archivo local es un directorio', 'Path file local is a directory'

        if not os.access(permissions):
            return False, 'No se tiene permisos necesarios sobre la ruta local', 'Path do not have permissions'

        return True, '',''

    @classmethod
    def interpret_error(cls, errorid, path):
        if errorid == cls.notsuch:
            return 'La ruta: "{}" no existe en el servidor remoto'.format(path)
        elif errorid == cls.acldenied:
            return 'No se tiene permisos sobre la ruta: "{}"'.format(path)
        elif errorid == cls.isdirectory:
            return 'La ruta proporcionada es un directorio, "{}"'.format(path)
        elif errorid == cls.alreadyexists:
            return 'La ruta ya existe en el servidor remoto, {}'.format(path)
        else:
            return 'Error desconocido sobre la ruta: "{}"'.format(path)

    def _get_exception(self):
        ''''''
        return ''.join(traceback.format_exception(*sys.exc_info()))

    del assert_connect,assure_function
