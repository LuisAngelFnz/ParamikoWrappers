# ParamikoWrappers

## Requerimientos
* Python 2.7

## Instalación(Paramiko)
python -m pip install paramiko==2.1.1

## Metodos disponibles hasta el momento(2022-12-30)

#### Retorna una tupla de 3 argumentos:
    success, message, result_or_error

* get
* get_to_buffer
* put
* put_from_str
* rmfile
* mkdir
* rmdir
* stat
* listdir
* rename
* chmod

#### Retorna un generador
* walk

#### Modo de uso


```python:
objsftp = sftp_util.SFTP()
success, message, error = obj_sftp.connect('your host','your use', 'your passs')
if not success:
    raise Exception('Your control error')
```
#### Ejemplo con walk y get_to_buffer
```python:
with objsftp as connection: # Cierra conexión en automatico aunque existan errores
    for success, error, (root, dirnames, filenames) in connection.walk('Your parent path'):
    
        if not success: # No se pudo leer root
            print('Error al leer root: {}'.format(root))
            continue
        
        for eachfilename in filenames:
            success, message, content_or_error = connection.get_to_buffer((root, eachfilename))
        
            if not success:
                print('Error in get file: {}, user_message: {}, traceback: {}'.format(
                    eachfilename,
                    message,
                    content_or_error
                ))
                continue
            
            ## Variable content_or_error un string del archivo remoto del servidor
```
