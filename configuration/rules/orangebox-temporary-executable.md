# OrangeBox Temporary Executable

Documentación de `orangebox-temporary-executable.xml`.

## Para qué sirve

Detecta ejecutables que aparecen o pasan a ser ejecutables dentro de:

- `/tmp/`
- `/var/tmp/`
- `/dev/shm/`

La regla no pregunta quién creó el archivo ni cómo se llama. Le interesa una sola cosa: **un archivo ejecutable apareció en un lugar donde no debería ser una forma normal de persistencia o ejecución**.

## Reglas

### 10410 — Archivo creado ya ejecutable

Parte de FIM `554` (archivo agregado).

Busca un archivo nuevo en los tres directorios temporales y verifica que sus permisos incluyan ejecución.

Ejemplo típico:

```bash
install -m 755 /dev/null /dev/shm/test
```

No se filtra por extensión porque un atacante puede llamar al ejecutable como quiera. Tampoco se inspecciona contenido: esa pega corresponde a otras capas, como YARA.

**Nivel 15:** un ejecutable nuevo en un directorio temporal merece atención inmediata.

### 10432 — Se agregó ejecución a un archivo existente

Parte de FIM `550` y exige que el cambio sea específicamente de permisos:

```text
changed_fields = permission
```

Además comprueba que el nuevo permiso contenga ejecución (`x`) o las variantes `s`/`t` cuando implican ejecución.

Esto permite detectar la clásica maniobra:

```bash
chmod 644 archivo
chmod 755 archivo
```

No se dispara simplemente porque cambie cualquier permiso.

## Por qué no se filtra por nombre o extensión

Porque sería muy fácil de esquivar. `malware.sh` es sospechoso, pero `update` también puede serlo si aparece ejecutable en `/dev/shm`.

La detección busca la propiedad que realmente interesa: **ejecución + directorio temporal**.

## Por qué no hay whitelist

Actualmente no hay excepciones autorizadas. Antes de silenciar una alerta hay que demostrar que el proceso es legítimo, de dónde viene y por qué necesita ejecutarse desde ese directorio.

## Dependencias

- Wazuh FIM/syscheck.
- `554`: archivo agregado.
- `550`: archivo modificado.

Esta capa detecta el comportamiento. No pretende decidir si el archivo es malware; para eso se puede complementar con YARA y otras evidencias.
