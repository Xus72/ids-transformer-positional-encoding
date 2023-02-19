# IDS - Transformer Positional Enconding

En este repositorio se va a resolver el problema de la detección de intrusos empleando el Transformer Positional Encoding. 
El problema consiste en clasificar el trafico de red como actividad normal o como ataque.

Este problema es un problema de espacio temporal, ya que puede haber comunicaciones entre los distintos dispositivos en las que se envie un paquete en un segundo u otras en las que se envien numerosos paquetes en un segundo, de modo que habrá casos en los que solo se genere una fila y otros casos en los que se generen múltiples filas.

## Dataset
El dataset que se va a usar es el [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html).

Este dataset contiene la actividad normal (BENIGN) y los ataques más comunes, como Brute Force, DDoS, Web Attack, etc.

El dataset representa el tráfico de red de lunes a viernes en horario laboral y está divido en varios csv que representan un día de la semana laboral, un periódo de tiempo (mañana o tarde) y un tipo de ataque. De modo que queda organizado de la siguiente manera:
    <ul>
        <li>Lunes, actividad normal</li>
        <li>Martes, ataques + actividad normal</li>
        <li>Miércoles, ataques + actividad normal</li>
        <li>Jueves, ataques + actividad normal</li>
        <li>Viernes, ataques + actividad normal</li>
    </ul>

El dataset se ha generado a partir del procesamiento de un fichero de paquetes de red a través de CICFlowMeter.

### Columnas
Cada csv está compuesto por un total de 79 columnas, la definición de cada columna la podemos encontrar en el repositorio de [CICFlowMeter](https://github.com/ahlashkari/CICFlowMeter/blob/master/ReadMe.txt).

La columna **Label** representa la clasificación que se le ha asignado al tráfico. Es decir, si se trata de un ataque (Brute Force, DDoS, Web Attack, etc.) o de la actividad normal de la red.

Los datos de las columnas están comprendidos en los siguientes rangos:
```
columns = df.columns
columns = columns[:-1]
for col in columns:
  min = df[col].min()
  max = df[col].max()
  print('{0}, Min: {1}, Max: {2}'.format(col,min,max))

### Output
Destination Port, Min: 0, Max: 65535
 Flow Duration, Min: -13, Max: 119999998
 Total Fwd Packets, Min: 1, Max: 219759
 Total Backward Packets, Min: 0, Max: 291922
Total Length of Fwd Packets, Min: 0, Max: 12900000
 Total Length of Bwd Packets, Min: 0, Max: 655453030
 Fwd Packet Length Max, Min: 0, Max: 24820
 Fwd Packet Length Min, Min: 0, Max: 2325
 Fwd Packet Length Mean, Min: 0.0, Max: 5940.857143
 Fwd Packet Length Std, Min: 0.0, Max: 7125.5968458437
Bwd Packet Length Max, Min: 0, Max: 19530
 Bwd Packet Length Min, Min: 0, Max: 2896
 Bwd Packet Length Mean, Min: 0.0, Max: 5800.5
 Bwd Packet Length Std, Min: 0.0, Max: 8194.66015625
Flow Bytes/s, Min: -261000000.0, Max: inf
 Flow Packets/s, Min: -2000000.0, Max: inf
 Flow IAT Mean, Min: -13.0, Max: 120000000.0
 Flow IAT Std, Min: 0.0, Max: 84800264.0
 Flow IAT Max, Min: -13, Max: 120000000
 Flow IAT Min, Min: -14, Max: 120000000
Fwd IAT Total, Min: 0, Max: 120000000
 Fwd IAT Mean, Min: 0.0, Max: 120000000.0
 Fwd IAT Std, Min: 0.0, Max: 84602928.0
 Fwd IAT Max, Min: 0, Max: 120000000
 Fwd IAT Min, Min: -12, Max: 120000000
Bwd IAT Total, Min: 0, Max: 120000000
 Bwd IAT Mean, Min: 0.0, Max: 120000000.0
 Bwd IAT Std, Min: 0.0, Max: 84418016.0
 Bwd IAT Max, Min: 0, Max: 120000000
 Bwd IAT Min, Min: 0, Max: 120000000
Fwd PSH Flags, Min: 0, Max: 1
 Bwd PSH Flags, Min: 0, Max: 0
 Fwd URG Flags, Min: 0, Max: 1
 Bwd URG Flags, Min: 0, Max: 0
 Fwd Header Length, Min: -32212234632, Max: 4644908
 Bwd Header Length, Min: -1073741320, Max: 5838440
Fwd Packets/s, Min: 0.0, Max: 3000000.0
 Bwd Packets/s, Min: 0.0, Max: 2000000.0
 Min Packet Length, Min: 0, Max: 1448
 Max Packet Length, Min: 0, Max: 24820
 Packet Length Mean, Min: 0.0, Max: 3337.142857
 Packet Length Std, Min: 0.0, Max: 4731.522394
 Packet Length Variance, Min: 0.0, Max: 22400000.0
FIN Flag Count, Min: 0, Max: 1
SYN Flag Count, Min: 0, Max: 1
 RST Flag Count, Min: 0, Max: 1
 PSH Flag Count, Min: 0, Max: 1
 ACK Flag Count, Min: 0, Max: 1
 URG Flag Count, Min: 0, Max: 1
 CWE Flag Count, Min: 0, Max: 1
 ECE Flag Count, Min: 0, Max: 1
 Down/Up Ratio, Min: 0, Max: 156
 Average Packet Size, Min: 0.0, Max: 3893.333251953125
 Avg Fwd Segment Size, Min: 0.0, Max: 5940.857143
 Avg Bwd Segment Size, Min: 0.0, Max: 5800.5
 Fwd Header Length.1, Min: -32212234632, Max: 4644908
Fwd Avg Bytes/Bulk, Min: 0, Max: 0
 Fwd Avg Packets/Bulk, Min: 0, Max: 0
 Fwd Avg Bulk Rate, Min: 0, Max: 0
 Bwd Avg Bytes/Bulk, Min: 0, Max: 0
 Bwd Avg Packets/Bulk, Min: 0, Max: 0
Bwd Avg Bulk Rate, Min: 0, Max: 0
Subflow Fwd Packets, Min: 1, Max: 219759
 Subflow Fwd Bytes, Min: 0, Max: 12870338
 Subflow Bwd Packets, Min: 0, Max: 291922
 Subflow Bwd Bytes, Min: 0, Max: 655453030
Init_Win_bytes_forward, Min: -1, Max: 65535
 Init_Win_bytes_backward, Min: -1, Max: 65535
 act_data_pkt_fwd, Min: 0, Max: 213557
 min_seg_size_forward, Min: -536870661, Max: 138
Active Mean, Min: 0.0, Max: 110000000.0
 Active Std, Min: 0.0, Max: 74200000.0
 Active Max, Min: 0, Max: 110000000
 Active Min, Min: 0, Max: 110000000
Idle Mean, Min: 0.0, Max: 120000000.0
 Idle Std, Min: 0.0, Max: 76900000.0
 Idle Max, Min: 0, Max: 120000000
 Idle Min, Min: 0, Max: 120000000
```

### Filas
Cada fila del dataset representa un flujo de datos de red, que es clasificado como una actividad normal de la red o un ataque. Cada fila se genera a partir de la captura de los paquetes resultantes de la interacción entre los dispositivos de la red con el del atacante.
