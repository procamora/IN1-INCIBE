from typing import NoReturn

import numpy
import pandas as pd
import json
import csv
import os
import re
import matplotlib.pyplot as plt
import configparser
import argparse
import time
#import seaborn as sns
import umap
#import hdbscan
from sklearn.cluster import KMeans
#from sklearn.manifold import TSNE
#from sklearn.decomposition import PCA
from timeit import default_timer as timer
from sklearn.model_selection import train_test_split, GridSearchCV
from matplotlib import cm
from sklearn.metrics import silhouette_samples
from sklearn.preprocessing import LabelEncoder
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from apyori import apriori
from sklearn.metrics import precision_recall_fscore_support
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import SGDClassifier
from sklearn import metrics
from sklearn.metrics import accuracy_score

from threatLevel import ThreatLevel
#from functions import getLogger

import requests
from elasticsearch import Elasticsearch
from typing import NoReturn, Dict

class MachineLearning(object):

    def __init__(self):
        #self._logger = logger
        self._doc_type = 'object'  # object y nested
        self._URL = "http://127.0.0.1:8080"
        self._size = 1000

    def request_objets_elastichsearch(self,workingDir) -> NoReturn:

        es = Elasticsearch([{'host': 'localhost', 'port': 9200}])
        data = es.search(index="output-scriptzteam", scroll='2m', size=self._size, body={"query": {"exists" : { "field" : "input" }}})
        #res=es.get(index='output-scriptzteam',doc_type=self._doc_type,id=215059)
        #print(res)

        # Get the scroll ID
        sid = data['_scroll_id']
        scroll_size = len(data['hits']['hits'])

        # Before scroll, process current batch of hits
        arrayJSON = []
        self.process_hits(data['hits']['hits'],arrayJSON)

        while scroll_size > 0:
            "Scrolling..."
            data = es.scroll(scroll_id=sid, scroll='2m')

            # Process current batch of hits
            all_data = self.process_hits(data['hits']['hits'],arrayJSON)

            # Update the scroll ID
            sid = data['_scroll_id']

            # Get the number of results that returned in the last scroll
            scroll_size = len(data['hits']['hits'])

        #Generacion del TL y ficheros CSVs
        self.calculate_ThreatLevel(arrayJSON,workingDir)

    def process_hits(self, hits: Dict, arrayJSON):
        """
        Metodo encargado de obtener para cada session de ElasticSearch todos los comando almacenados.
        Cada session es almacenada en un diccionario, siendo la clave la session y el valor los comando introducidos.
        :param hits:
        :param arrayJSON:
        :return arrayJSON:
        """

        for hit in hits:
            session = hit['_source']['session']
            if len(arrayJSON) > 0:
                #Variable para controlar la insercción de una session nueva
                insert = False
                for i in range(0, len(arrayJSON)):
                    if session in arrayJSON[i]:
                        arrayJSON[i][session].append(hit['_source']['input'])
                        insert = True
                        break
                if not insert:
                    inputs = []
                    inputs.append(hit['_source']['input'])
                    newJSON = {session : inputs}
                    arrayJSON.append(newJSON)

            else:
                inputs = []
                inputs.append(hit['_source']['input'])
                newJSON = {session : inputs}
                arrayJSON.append(newJSON)

        return arrayJSON

    def calculate_ThreatLevel(self,arrayJSON,workingDir):
        """
        A partir de la lista de comando de cada session se calcula el nivel de amenaza.
        Además se generan los ficheros CSVs para train y test
        :param arrayJSON:
        :return:
        """
        label_dict = {}
        data = []
        for i in range(0, len(arrayJSON)):
            for key in arrayJSON[i]:
                list_commands = []
                #Doble bucle por tenemos un array dentro de otro
                for values in arrayJSON[i].values():
                    for command in values:
                        list_commands.append(command)
                threatLevel = ThreatLevel()
                newJSON = {
                    'IdSession' : key,
                    'threatLevel': threatLevel.get_threat_level_1(list_commands),
                    'listInputs' : arrayJSON[i].get(key)
                }
                data.append(newJSON)



        self.createFileCSV(workingDir,"all_data",data,label_dict)

        #import csv files from folder
        combined_csv = pd.concat([pd.read_csv(workingDir+f) for f in os.listdir(workingDir) if(f.find(".csv")>0)]).set_index('IdSession')

        #Dividimos todos los datos en train y evaluation
        self.separate_train_evaluatio(workingDir,combined_csv)

    def getJSON(self,fileJSON):
        """
        Metodo encargado de convertir los ficheros en texto plano a JSON. Ademas, es el metodo
        encargado de etiquetar los vectores en base a los comandos ejecutados y su threatlevel
        :param fileJSON:
        :return:
        """
        data = []
        with open(fileJSON) as file:
            for line in file:
                #data.append(json.loads(line))
                lineJSON = json.loads(line)

                command_list = []
                #Obtenemos todos los comandos de cada sesion para re-calcular el threatLevel
                for i in range(0,len(lineJSON['listInputs'])):
                    if len(lineJSON['listInputs'])>0 and lineJSON["listInputs"][i]["input"]!='':
                        command_list.append(lineJSON["listInputs"][i]["input"])
                #Calculamos el threatLevel de las sesiones que tienen comando
                if len(command_list)>0:
                    threatLevel = threatLevel()
                    threatLevel = threatLevel.getThreatLevel(command_list)

                    newJSON = {
                        'IdSession' : lineJSON['IdSession'],
                        'threatLevel': threatLevel,
                        'listInputs' : lineJSON['listInputs']
                    }
                else:
                    newJSON = {
                        'IdSession' : lineJSON['IdSession'],
                        'threatLevel': lineJSON['threatLevel'],
                        'listInputs' : lineJSON['listInputs']
                    }
                data.append(newJSON)
        return data

    def JSONToCSV(self,workingDir) -> NoReturn:
        """
        Función encargada de convertir los ficheros JSON en CSV para poder ser interpretados
        posteriormente por el algoritmo de clustering y para aplicar onehotencode
        :return:
        """

        label_dict = {}

        #Obtenemos JSONs de los diferentes ficheros.

        fileList = os.listdir(workingDir)
        for file in fileList:
            if(file.find(".json")>0):
                dataCompleted = self.getJSON(workingDir+file)
                withoutextension = file.split(".json")
                self.createFileCSV(workingDir,withoutextension[0],dataCompleted,label_dict)

        #import csv files from folder
        combined_csv = pd.concat([pd.read_csv(workingDir+f) for f in os.listdir(workingDir) if(f.find(".csv")>0)]).set_index('IdSession')
        #combined_csv.to_csv(workingDir+"combined_csv.csv",index=False)

        #Dividimos todos los datos en train y evaluation
        self.separate_train_evaluatio(workingDir,combined_csv)



    def createFileCSV(self, workingDir,withoutextension, dataCompleted, label_dict) -> NoReturn:
        """
        Metodo encargado de generar un fichero CSV con la estructura acorde a nuestro planteamiento.
        Cada vector estara compuesto por 0's y 1's dependiendo de las acciones que puedan realizar los
        atacantes con los comandos introducidos.
        :param name:
        :param dataCompleted:
        :param dataSession:
        :param dataNoSession:
        :param option:
        :return:
        """

        F_leer_disco = ['history', 'cat', 'echo', 'df','cp','mv', 'pkill','mount','passwd','dd']

        F_escribir_disco = ['cat', 'sed', 'rm','cp','chmod','mkdir','mv',
                            'touch','mount','passwd','dd']

        F_conexiones_internet = ['wget', 'ssh', 'tftp', 'tftpd','scp','nc','curl','ftpget']

        F_instalacion_compilacion_programas = ['apt-get', 'apt', 'yum', 'dnf', 'if', 'while', 'do', 'else','done',
                                               'tar', 'gcc', 'make','chmod', 'bzip2', 'chown']

        F_ejecucion_programas = ['nohup','sudo','python','perl','sh','bash','busybox','exec']

        F_matar_suspender_procesos = ['kill', 'killall', 'pkill',
                                      'poweroff','reboot','halt','reSuSEfirewall', 'SuSEfirewall','sleep']

        F_obtencion_informacion = ['cd', 'cat', 'chkconfig', 'echo', 'du', 'df', 'uptime', 'w', 'whoami', 'ifconfig',
                                   'netstat', 'last', 'ls', 'ulimit', 'uname', 'history','export','unset', 'set']

        data_vectors = []

        #Solo tiene en cuenta las sesiones con comandos
        for i in dataCompleted:
            if len(i["listInputs"]) > 0:
                current_vector = [0,0,0,0,0,0,0,0,0]
                current_vector[0] = i["IdSession"]
                #print("Nueva session: ",current_vector[0])
                #print(i["listInputs"])
                for j in range(0,len(i["listInputs"])):
                    #file.writerow([i["IdSession"],i["listInputs"][j]["input"]])
                    if (i["listInputs"][j]!=''):
                        current_command = i["listInputs"][j].split(' ')[0]
                        #Comprobamos si el comando está dentro de cada feature
                        if current_command in F_leer_disco:
                            #print('Leer Disco: ',current_command)
                            current_vector[1] = 1
                        if current_command in F_escribir_disco:
                            #print('Escribir Disco: ',current_command)
                            current_vector[2] = 1
                        if current_vector == 'history -c' or current_vector == 'history -d':
                            #print('Escribir Disco: ',current_command)
                            current_vector[2] = 1
                        if current_command in F_conexiones_internet:
                            #print('Conexion Int.: ',current_command)
                            current_vector[3] = 1
                        if current_command in F_instalacion_compilacion_programas:
                            #print('Install and make: ',current_command)
                            current_vector[4] = 1
                        #if any(substring in current_command for substring in F_compilacion_programas):
                        #current_vector[5] = 1
                        if current_command in F_ejecucion_programas:
                            #print('Ejecucion: ',current_command)
                            current_vector[5] = 1
                        if current_command in F_matar_suspender_procesos:
                            #print('Suspender: ',current_command)
                            current_vector[6] = 1
                        if current_command in F_obtencion_informacion:
                            #print('Info: ',current_command)
                            current_vector[7] = 1
                        # Si no ha hecho matching con ninguna lista lo ponemos como obtencion de informacion
                    if current_vector == [i["IdSession"],0,0,0,0,0,0,0,0] and i["listInputs"][j]!='':
                        current_vector[7] = 1
                #Añadimos las etiquetas de cada IdSession a un diccionario
                if i["threatLevel"] != '':
                    label_dict[i["IdSession"]] = i["threatLevel"]
                    current_vector [8] = i["threatLevel"]
                data_vectors.append(current_vector)

        df = pd.DataFrame(data_vectors,columns=['IdSession','F_leer_disco','F_escribir_disco','F_conexiones_internet','F_instalacion_compilacion_programas','F_ejecucion_programas','F_matar_suspender_procesos','F_obtencion_informacion','threatLevel']).set_index('IdSession')
        df.to_csv(workingDir+withoutextension+'.csv')

    def separate_train_evaluatio(self, workingDir, df) -> NoReturn:

        #Dividimos el dataset en entrenamiento y evaluacion para poder hacer clasificacion
        X_train, X_evaluation = train_test_split(df, test_size = 0.20)

        X_train.to_csv(workingDir+"train_data.csv")
        X_evaluation.to_csv(workingDir+"evaluation_data.csv")

    def onehotEncoding(self, workingDir) -> NoReturn:
        """
        Convierte la feature input(variable categorica) en una binarizacion (onehotencode). Es decir, cada comando diferente
        introducido es codificado con 0's y 1's, ya que los string no son interpretados de forma correcta por los algoritmos
        a la hora de establecer relaciones.
        :return:
        """
        #Cargamos el fichero .csv
        dataFrame = pd.read_csv(workingDir+"combined_csv.csv",index_col=0)

        #Eliminamos la columna vacia Unnamed introducida de forma automatica al no tener indice
        #dataFrame.drop('Unnamed: 0', axis=1, inplace=True)

        #Aplicamos onehotencode.
        #Get_dummies aplica onehotencode a la columna de string indicada, dejando el resto de columnas sin tocar.
        #Con axis = 1 le indicamos que aplica onehotencode a toda la columna input
        dataFrame = pd.concat([dataFrame, pd.get_dummies(dataFrame['input'], prefix='input')], axis=1)

        #Borramos la antigua columna input con los comandos en forma de string
        dataFrame.drop(['input'], axis=1, inplace=True)

        #Agrupamos todos los comandos de una misma sesion en una sola fila (vector)
        dataFrame = dataFrame.groupby(['IdSession']).sum().reset_index()
        #dataFrame.to_csv("/Users/josemariajorqueravalero/Desktop/JSON_Pablo/prueba1.csv", sep='\t', encoding='utf-8')

        #Calculamos el mínimo entre 1 y la suma, dado que no nos interesa las repeticiones de una mismo comando
        #Sino saber si se ha ejecutado solo

        df = dataFrame.as_matrix()
        start = timer()
        for i in range(0,dataFrame.shape[0]):
            for j in range(1,dataFrame.shape[1]):
                df[i][j] = min(1,df[i][j])
        end = timer()

        print('Tiempo fichero: {}'.format(end - start))

        #Devolvemos la matrix a un DataFrame panda.
        #List es para obtener los nombres de las columnas y los asignamos al nuevo dataFrame
        df = pd.DataFrame(df,columns=list(dataFrame))
        #df.to_csv(workingDir+'train_evaluation_data.csv')

        #Dividimos el dataset en entrenamiento y evaluacion para poder hacer clasificacion
        X_train, X_evaluation = train_test_split(df, test_size = 0.20)
        #Establecemos el indice numero ordenado de nuevo
        X_train = X_train.reset_index()
        X_evaluation = X_evaluation.reset_index()
        #Eliminamos la columna index que se genera
        X_train = X_train.drop('index', axis=1)
        X_evaluation = X_evaluation.drop('index', axis=1)
        X_train.to_csv(workingDir+"train_data.csv")
        X_evaluation.to_csv(workingDir+"evaluation_data.csv")

    def clustering(self, workingDir) -> NoReturn:

        dataFrame = self.read_CSV(workingDir)

        #Reducir dimensiones
        #data = umap.UMAP( n_neighbors=5,min_dist=0.1).fit_transform(dataFrame)

        #Calcular método del codo
        #elbowMethor(data)

        #Establecemos el nº de clusters
        kmeans = KMeans(n_clusters=7,max_iter=400)
        # Fitting the input data
        kmeans = kmeans.fit(dataFrame)
        #Predice el indice de cada muestra y lo asigna a un cluster
        labels = kmeans.predict(dataFrame)
        #silhouette_plots(data, labels, workingDir)

        #Centroid values
        centroids = kmeans.cluster_centers_
        #print(centroids)

        #Nueva columna que almacenara el nº de cluster para cada sesion
        new_colum = []
        #Creamos un conjunto de datos por cluster
        data_cluster_0,data_cluster_1,data_cluster_2,data_cluster_3,data_cluster_4,data_cluster_5,data_cluster_6 = [],[],[],[],[],[],[]

        #Obtenemos un nuevo dataFrame pero con indice para obtener los clusters
        dataFrame_2 = pd.read_csv(workingDir+"train_data.csv")
        dataFrame_2 = dataFrame_2.iloc[:,1:]
        df = dataFrame_2.as_matrix()

        num0,num1,num2,num3,num4,num5,num6 = 0,0,0,0,0,0,0
        #Identificacion de cada cluster en la grafica
        for i in range(0, len(dataFrame)):
            new_colum.append(kmeans.labels_[i])
            if kmeans.labels_[i] == 0:
                num0+=1
                #c0 = plt.scatter(dataFrame[i,0],dataFrame[i,1],c='g')
                data_cluster_0.append(df[i])
            elif kmeans.labels_[i] == 1:
                num1+=1
                #c1 = plt.scatter(dataFrame[i,0],dataFrame[i,1],c='r')
                data_cluster_1.append(df[i])
            elif kmeans.labels_[i] == 2:
                num2+=1
                #c2 = plt.scatter(dataFrame[i,0],dataFrame[i,1],c='c')
                data_cluster_2.append(df[i])
            elif kmeans.labels_[i] == 3:
                num3+=1
                #c3 = plt.scatter(dataFrame[i,0],dataFrame[i,1],c='m')
                data_cluster_3.append(df[i])
            elif kmeans.labels_[i] == 4:
                num4+=1
                #c4 = plt.scatter(dataFrame[i,0],dataFrame[i,1],c='y')
                data_cluster_4.append(df[i])
            elif kmeans.labels_[i] == 5:
                num5+=1
                #c5 = plt.scatter(dataFrame[i,0],dataFrame[i,1],c='k')
                data_cluster_5.append(df[i])
            elif kmeans.labels_[i] == 6:
                num6+=1
                #c6 = plt.scatter(dataFrame[i,0],dataFrame[i,1],c='b')
                data_cluster_6.append(df[i])

        print('Cluster 0:',num0,'Cluster 1:',num1,'Cluster 2:',num2,'Cluster 3:',num3,'Cluster 4:',num4,'Cluster 5:',num5,'Cluster 6:',num6)
        """
        Recorremos cada cluster y generamos un fichero .csv para cada uno
        El objetivo es posteriomente sacar asociación de reglas de cada cluster
        """
        start = timer()
        for i in range(7):
            df_empty = dataFrame_2[0:0]
            if(i==0):
                new_df = pd.DataFrame(data_cluster_0)
                new_df.columns = list(df_empty)
                new_df['Cluster'] = [0]*len(new_df)
                self.data_for_cluster(workingDir,'cluster_0.csv',new_df)
            elif(i==1):
                new_df = pd.DataFrame(data_cluster_1)
                new_df.columns = list(df_empty)
                new_df['Cluster'] = [1]*len(new_df)
                self.data_for_cluster(workingDir,'cluster_1.csv',new_df)
            elif(i==2):
                new_df = pd.DataFrame(data_cluster_2)
                new_df.columns = list(df_empty)
                new_df['Cluster'] = [2]*len(new_df)
                self.data_for_cluster(workingDir,'cluster_2.csv',new_df)
            elif(i==3):
                new_df = pd.DataFrame(data_cluster_3)
                new_df.columns = list(df_empty)
                new_df['Cluster'] = [3]*len(new_df)
                self.data_for_cluster(workingDir,'cluster_3.csv',new_df)
            elif(i==4):
                new_df = pd.DataFrame(data_cluster_4)
                new_df.columns = list(df_empty)
                new_df['Cluster'] = [4]*len(new_df)
                self.data_for_cluster(workingDir,'cluster_4.csv',new_df)
            elif(i==5):
                new_df = pd.DataFrame(data_cluster_5)
                new_df.columns = list(df_empty)
                new_df['Cluster'] = [5]*len(new_df)
                self.data_for_cluster(workingDir,'cluster_5.csv',new_df)
            elif(i==6):
                new_df = pd.DataFrame(data_cluster_6)
                new_df.columns = list(df_empty)
                new_df['Cluster'] = [6]*len(new_df)
                self.data_for_cluster(workingDir,'cluster_6.csv',new_df)
        end = timer()

        print('Tiempo generacion ficheros: {}'.format(end - start))

        #Añadir una nueva columna al dataframe con el indice del cluster y guardar en otro fichero auxiliar
        new_dataFrame = dataFrame
        new_dataFrame['Cluster'] = new_colum
        new_dataFrame.to_csv(workingDir+"label_train_data.csv")

        #plt.legend([c0, c1, c2, c3, c4,c5,c6],['Cluster 0','Cluster 1','Cluster 2','Cluster 3','Cluster 4','Cluster 5','Cluster 6'])
        #plt.scatter(centroids[:, 0], centroids[:, 1], marker='*', c='black', s=50)
        #plt.title('K-means clusters(UMAP)')

        # Create target Directory if don't exist
        #if not os.path.exists(workingDir+'clustering'):
        #os.mkdir(workingDir+'clustering')
        #plt.savefig(workingDir+'clustering/'+'INDICAR_PARAMETROS_CONFIGURACION'+'.png')
        #else:
        #plt.savefig(workingDir+'clustering/'+'INDICAR_PARAMETROS_CONFIGURACION'+'.png')

        #plt.clf()

    """
    Funcion para escribir los diferentes cluster a csv
    """
    def data_for_cluster(self, workingDir, name, new_df) -> NoReturn:
        if not os.path.exists(workingDir+name):
            #Establecemos el IdSession como indice
            #new_df.set_index(new_df["IdSession"].values, inplace=True)
            #Eliminamos esa columna de la tabla
            #new_df=new_df.iloc[:,1:]
            new_df.to_csv(workingDir+name)
        else:
            #Establecemos el IdSession como indice
            #new_df.set_index(new_df["IdSession"].values, inplace=True)
            #Eliminamos esa columna de la tabla
            #new_df=new_df.iloc[:,1:]
            new_df.to_csv(workingDir+name)

    def apriori_algorithm(self, workingDir) -> NoReturn:

        """
        Ponemos la cabecera como primera linea  de la matriz para poder acceder a ella
        tras tranformar el array a un numpy
        El tiempo en leer el array 2D de prueba es de 13s
        Tiempo entre lectura y generar reglas 160s
        """
        start = time.time()
        """
        Leemos todos los ficheros CSV generados para cada cluster
        """
        fileList = os.listdir(workingDir)
        for file in fileList:
            if(re.match(r'cluster_[0-9].csv',file)):
                #Bajamos la cabecera de la columnas a la primera linea para poder acceder a ella
                dataFrame = pd.read_csv(workingDir+file,header=None)
                #Lista global de listas internas donde se almacena cada sesion y sus comandos introducidos
                global_list = []
                #Convertimos el array a numpy para hacer el acceso mas eficiente~
                #Obtenemos para da IDSession solo los comandos introducidos
                df = dataFrame.as_matrix()

                for i in range(1, dataFrame.shape[0]):
                    list_inner = []
                    for j in range(1, dataFrame.shape[1]):
                        if(df[0,j]!='Cluster'):
                            if(df[i,j]=='1'):
                                # Accedemos a la cabecera de la columna y obtenemos el comando
                                list_inner.append(str(df[0,j].split('input_')[1]))

                    global_list.append(list_inner)

                """
                Ajustar parametros en proporcionan al numero de vectores en cada cluster
                """
                association_rules = apriori(global_list, min_length=4, min_support=0.0045, min_confidence=0.2, min_lift=1)
                #association_results = list(association_rules)

                cluster_rules = []
                for item in association_rules:

                    # first index of the inner list
                    # Contains base item and add item
                    pair = item[0]
                    items = [x for x in pair]
                    if(len(items)>3):

                        current_rule = "Rule: " + items[0] + " -> " + items[1]+ " -> " + items[2]+ " -> " + items[3]+"\n"
                        #Añadimos las reglas que no esten añadidas ya
                        if(current_rule not in cluster_rules):
                            cluster_rules.append("Rule: " + items[0] + " -> " + items[1]+ " -> " + items[2]+ " -> " + items[3]+"\n")

                            #second index of the inner list
                            cluster_rules.append("Support: " + str(item[1])+"\n")

                            #third index of the list located at 0th of the third index of the inner list
                            cluster_rules.append("Confidence: " + str(item[2][0][2])+"\n")
                            cluster_rules.append("Lift: " + str(item[2][0][3])+"\n")
                            cluster_rules.append("=====================================\n")
                """
                Guardamos en las reglas de cada cluster
                """
                filehandle = open(workingDir+file.split(".csv")[0]+"_rules.txt", "w")
                filehandle.writelines(cluster_rules)
                filehandle.close()
        end = time.time()

        print('Tiempo leer array 2D y calcular reglas: {}'.format(end - start))

    def new_apriori_algorithm(self, workingDir) -> NoReturn:

        """
        Ponemos la cabecera como primera linea  de la matriz para poder acceder a ella
        tras tranformar el array a un numpy
        El tiempo en leer el array 2D de prueba es de 13s
        Tiempo entre lectura y generar reglas 160s
        """
        start = time.time()

        #Bajamos la cabecera de la columnas a la primera linea para poder acceder a ella
        dataFrame = pd.read_csv(workingDir+'train_data.csv',header=None)
        #Lista global de listas internas donde se almacena cada sesion y sus comandos introducidos
        global_list = []
        #Convertimos el array a numpy para hacer el acceso mas eficiente~
        #Obtenemos para da IDSession solo los comandos introducidos
        df = dataFrame.as_matrix()

        for i in range(1, dataFrame.shape[0]):
            list_inner = []
            for j in range(1, dataFrame.shape[1]):
                if(df[0,j]!='Cluster'):
                    if(df[i,j]=='1'):
                        # Accedemos a la cabecera de la columna y obtenemos el comando
                        list_inner.append(str(df[0,j].split('input_')[1]))

            global_list.append(list_inner)

        """
        Ajustar parametros en proporcionan al numero de vectores en cada cluster
        """
        support_minimo = 50 / len(df)
        association_rules = apriori(global_list, min_length=4, min_support=support_minimo, min_confidence=0.2, min_lift=2)
        #association_results = list(association_rules)

        cluster_rules = []
        for item in association_rules:

            # first index of the inner list
            # Contains base item and add item
            pair = item[0]
            items = [x for x in pair]
            if(len(items)>3):

                current_rule = "Rule: " + items[0]
                for i in range(1,len(items)):
                    current_rule+= " -> "+items[i]

                current_rule+="\n"
                #Añadimos las reglas que no esten añadidas ya
                #if(current_rule not in cluster_rules):
                cluster_rules.append("Rule: " + items[0] + " -> " + items[1]+ " -> " + items[2]+ " -> " + items[3]+"\n")

                #second index of the inner list
                cluster_rules.append("Support: " + str(item[1])+"\n")
                #third index of the list located at 0th of the third index of the inner list
                cluster_rules.append("Confidence: " + str(item[2][0][2])+"\n")
                cluster_rules.append("Lift: " + str(item[2][0][3])+"\n")
                cluster_rules.append("=====================================\n")
        """
        Guardamos en las reglas de cada cluster
        """
        filehandle = open(workingDir+'all_rules.txt', "w")
        filehandle.writelines(cluster_rules)
        filehandle.close()
        end = time.time()

        print('Tiempo leer array 2D y calcular reglas: {}'.format(end - start))

    def elbowMethod(self, workingDir) -> NoReturn:
        dataFrame = self.read_CSV(workingDir)
        """
            Indicar los parametros apropiados para UMAP ya que previamente
            han sido calculados
        """
        data = umap.UMAP(n_neighbors=5,min_dist=0.1).fit_transform(dataFrame)
        Sum_of_squared_distances = []
        for k in range(2,11):
            km = KMeans(n_clusters=k)
            km = km.fit(data)
            Sum_of_squared_distances.append(km.inertia_)
            print(k,km.inertia_)

        plt.plot(range(2,11), Sum_of_squared_distances, 'bx-')
        plt.xlabel('Number of clusters')
        plt.ylabel('Distortion')
        plt.title('Elbow Method For Optimal k')
        if not os.path.exists(workingDir+'clustering'):
            os.mkdir(workingDir+'clustering')
            plt.savefig(workingDir+'clustering/'+'Elbow.png')
        else:
            plt.savefig(workingDir+'clustering/'+'Elbow.png')

        plt.clf()

    def silhouette_plots(self, data, labels, workingDir) -> NoReturn:
        cluster_lables = numpy.unique(labels)
        n_cluster = cluster_lables.shape[0]
        silhouette_vals = silhouette_samples(data,labels, metric='euclidean')
        y_ax_lower, y_ax_uper = 0,0
        yticks = []

        for i, c in enumerate(cluster_lables):
            c_silhouette_vals = silhouette_vals[labels == c]
            c_silhouette_vals.sort()
            y_ax_uper += len(c_silhouette_vals)
            color = cm.jet(float(i) / n_cluster)
            plt.barh(range(y_ax_lower,y_ax_uper), c_silhouette_vals,height=1.0,color=color)
            yticks.append((y_ax_lower+y_ax_uper)/2.)
            y_ax_lower += len(c_silhouette_vals)
        silhouette_avg = numpy.mean(silhouette_vals)
        plt.axvline(silhouette_avg,color='red',linestyle='--')
        plt.yticks(yticks,cluster_lables+1)
        plt.ylabel('Cluster')
        plt.xlabel('Silhouette coefficient')
        plt.title('Silhouette For Optimal k=X')

        if not os.path.exists(workingDir+'clustering'):
            os.mkdir(workingDir+'clustering')
            plt.savefig(workingDir+'clustering/'+'Silhouette.png')
        else:
            plt.savefig(workingDir+'clustering/'+'Silhouette.png')

        plt.clf()

    def labeled_IdSession(self, workingDir, label_dict) -> NoReturn:

        train = pd.read_csv(workingDir+"train_data.csv",index_col=0)
        evaluation = pd.read_csv(workingDir+"evaluation_data.csv",index_col=0)
        #labeled_IdSession = pd.read_csv(workingDir+"labeled_IdSession.csv",index_col=0)

        matrix_train = train.as_matrix()
        matrix_evaluation = evaluation.as_matrix()

        list_label_train, list_label_evaluation = [],[]

        for i in range(0, len(matrix_train)):
            idActual = matrix_train[i][0]
            print(idActual)
            list_label_train.append(label_dict[idActual])

        for i in range(0, len(matrix_evaluation)):
            idActual = matrix_train[i][0]
            list_label_evaluation.append(label_dict[idActual])

        train['label'] = list_label_train
        evaluation['label'] = list_label_evaluation

        train.to_csv(workingDir+'label_train_data.csv')
        evaluation.to_csv(workingDir+'label_evaluation_data.csv')


    def correlation_matrix(self, X_train, y_train) -> NoReturn:
        import sklearn
        informacion= sklearn.feature_selection.mutual_info_.mutual_info_classif(X_train,y_train)
        print(informacion)
        print(max(informacion))
        for score, fname in sorted(zip(informacion, X_train.columns.values), reverse=True)[:]:
            print(fname, score)

    def clasificador(self, workingDir) -> NoReturn:

        """
        Metodo encargado de obtener el dataset con todos los vectores etiquetados y dividiar en dos dataset
        train (80%) y test (20%). Acto seguido se lleva a cabo el calculo de los parámetros óptimos para cada
        algoritmo y su posterior ejecución.
        :param workingDir:
        :return:
        """

        #Obtenemos los datos de evaluacion etiquetados
        labeled_evaluation = pd.read_csv(workingDir+"evaluation_data.csv",index_col=0)
        y_evaluation=labeled_evaluation["threatLevel"]
        evaluation=labeled_evaluation.drop('threatLevel',axis=1)

        #Obtenemos los datos de entrenamiento etiquetados
        train = pd.read_csv(workingDir+"train_data.csv",index_col=0)
        #Eliminamos la columna vacia Unnamed introducida de forma automatica al no tener indice
        y_train=train["threatLevel"]
        X_train = train.drop('threatLevel',axis=1)

        #correlation_matrix(X_train,y_train)

        #Hacemos el tunnig parameter para K-nn -> {'algorithm': 'ball_tree', 'leaf_size': 1, 'n_jobs': -1, 'n_neighbors': 8, 'weights': 'distance'}
        #tuned_parameter_KNN(X_train,y_train)
        #tuned_parameter_DT(X_train,y_train)
        #tuned_parameter_RF(X_train,y_train)
        #tuned_parameter_svm(X_train,y_train)

        #Entrenando el algoritmo KNN
        knnclassifier = KNeighborsClassifier(n_neighbors=8, algorithm='ball_tree', leaf_size=1, n_jobs=-1, weights='distance')
        knnclassifier.fit(X_train,y_train)
        #Hacemos la prediccion
        X_evaluation = evaluation
        y_knn_predict = knnclassifier.predict(X_evaluation)

        print('Score train K-NN: ',knnclassifier.score(X_train,y_train))
        print('Score evaluation K-NN: ',knnclassifier.score(X_evaluation,y_evaluation))

        precision_knn, recall_knn, fscore_knn, support_knn = precision_recall_fscore_support(y_evaluation, y_knn_predict)

        print('Precision por clases: ',precision_knn)
        print('Precision k-nn: ', sum(precision_knn)/len(precision_knn))
        print('Recall por clases: ',recall_knn)
        print('Recall k-nn: ', sum(recall_knn)/len(recall_knn))
        print('F1-score por clases: ',fscore_knn)
        print('F1-score k-nn: ', sum(fscore_knn)/len(fscore_knn))
        print('Accuracy k-nn: ',accuracy_score(y_evaluation, y_knn_predict))
        print('Support k-nn: ',support_knn)
        #fpr, tpr, thresholds = metrics.roc_curve(y_evaluation, y_knn_predict, pos_label=2)
        #print('AUC: ',metrics.auc(fpr, tpr))
        print()

        #Hacemos el tunning parameter para DT-> {'max_features': 'auto', 'min_samples_leaf': 1, 'min_samples_split': 2, 'random_state': 123}
        #tuned_parameter_DT(X_train,y_train)

        #Entrenando Decision Tree
        DTclassifier = DecisionTreeClassifier(random_state = 123, max_features='auto', min_samples_leaf=1, min_samples_split=2)
        DTclassifier.fit(X_train, y_train)
        #Hacemos la prediccion
        X_evaluation = evaluation
        y_dt_predict = DTclassifier.predict(X_evaluation)

        print('Score train DT: ',DTclassifier.score(X_train,y_train))
        print('Score evaluation DT: ',DTclassifier.score(X_evaluation,y_evaluation))

        precision_dt, recall_dt, fscore_dt, support_dt = precision_recall_fscore_support(y_evaluation, y_dt_predict)

        print('Precision por clases: ',precision_dt)
        print('Precision DT: ', sum(precision_dt)/len(precision_dt))
        print('Recall por clases: ',recall_dt)
        print('Recall DT: ', sum(recall_dt)/len(recall_dt))
        print('F1-score por clases: ',fscore_dt)
        print('F1-score DT: ', sum(fscore_dt)/len(fscore_dt))
        print('Accuracy DT: ',accuracy_score(y_evaluation, y_dt_predict))
        print('Support DT: ',support_dt)
        #fpr, tpr, thresholds = metrics.roc_curve(y_evaluation, y_dt_predict, pos_label=2)
        #print('AUC: ',metrics.auc(fpr, tpr))
        print()

        #Hacemos el tunning parameter para RF -> {'criterion': 'gini', 'min_samples_leaf': 1, 'min_samples_split': 6, 'n_estimators': 30, 'n_jobs': -1, 'random_state': 123}
        #tuned_parameter_RF(X_train,y_train)

        #Entrenamos RandomForest
        rf = RandomForestClassifier(n_estimators = 30, random_state = 123, criterion='gini',min_samples_leaf=1, min_samples_split=6,n_jobs=-1)
        rf.fit(X_train, y_train)
        #Hacemos la prediccion
        X_evaluation = evaluation
        y_rf_predict = rf.predict(X_evaluation)

        print('Score train RF: ',rf.score(X_train,y_train))
        print('Score evaluation RF: ',rf.score(X_evaluation,y_evaluation))

        precision_rf, recall_rf, fscore_rf, support_rf = precision_recall_fscore_support(y_evaluation, y_rf_predict)

        print('Precision por clases: ',precision_rf)
        print('Precision RF: ', sum(precision_rf)/len(precision_rf))
        print('Recall por clases: ',recall_rf)
        print('Recall RF: ', sum(recall_rf)/len(recall_rf))
        print('F1-score por clases: ',fscore_rf)
        print('F1-score RF: ', sum(fscore_rf)/len(fscore_rf))
        print('Accuracy RF: ',accuracy_score(y_evaluation, y_rf_predict))
        print('Support RF: ',support_rf)
        #fpr, tpr, thresholds = metrics.roc_curve(y_evaluation, y_rf_predict, pos_label=2)
        #print('AUC: ',metrics.auc(fpr, tpr))
        #print(rf.feature_importances_)
        print()

        #Hacemos el tunnig parameter para SVM
        #tuned_parameter_svm(X_train,y_train)

        #Entrenando el algoritmo SVM -> {'C': 1000, 'gamma': 0.01, 'kernel': 'rbf'}
        svclassifier = SVC(kernel='rbf',C=1000,gamma=0.01)
        svclassifier.fit(X_train, y_train)
        #Hacemos la prediccion
        X_evaluation = evaluation
        y_svm_predict = svclassifier.predict(X_evaluation)

        print('Score train SVM: ',svclassifier.score(X_train,y_train))
        print('Score evaluation SVM: ',svclassifier.score(X_evaluation,y_evaluation))

        precision_svm, recall_svm, fscore_svm, support_svm = precision_recall_fscore_support(y_evaluation, y_svm_predict)

        print('Precision por clases: ',precision_svm)
        print('Precision SVM: ', sum(precision_svm)/len(precision_svm))
        print('Recall por clases: ',recall_svm)
        print('Recall SVM: ', sum(recall_svm)/len(recall_svm))
        print('F1-score por clases: ',fscore_svm)
        print('F1-score SVM: ', sum(fscore_svm)/len(fscore_svm))
        print('Accuracy SVM: ',accuracy_score(y_evaluation, y_svm_predict))
        print('Support SVM: ',support_svm)
        #fpr, tpr, thresholds = metrics.roc_curve(y_evaluation, y_svm_predict, pos_label=2)
        #print('AUC: ',metrics.auc(fpr, tpr))
        print()


    def tuned_parameter_svm (X_train, y_train):

        model=SVC()
        params = [{'kernel': ['rbf'], 'gamma': [1e-2, 1e-3, 1e-4, 1e-5],
                   'C': [0.001, 0.10, 0.1, 10, 25, 50, 100, 1000]},
                  {'kernel': ['sigmoid'], 'gamma': [1e-2, 1e-3, 1e-4, 1e-5],
                   'C': [0.001, 0.10, 0.1, 10, 25, 50, 100, 1000]},
                  {'kernel': ['linear'], 'C': [0.001, 0.10, 0.1, 10, 25, 50, 100, 1000]}
                  ]

        scores = ['precision'] #, 'recall']

        for score in scores:
            print("# Tuning hyper-parameters SVM for %s" % score)
            print()

            #Making models with hyper parameters sets
            model1 = GridSearchCV(model, param_grid=params, n_jobs=-1)
            #Learning
            model1.fit(X_train,y_train)
            #The best hyper parameters set
            print("Best Hyper Parameters SVM:\n",model1.best_params_)
            print()
            print("Grid scores on development set:")
            print()
            means = model1.cv_results_['mean_test_score']
            stds = model1.cv_results_['std_test_score']
            for mean, std, params in zip(means, stds, model1.cv_results_['params']):
                print("%0.3f (+/-%0.03f) for %r"
                      % (mean, std * 2, params))
            print()

    def tuned_parameter_SGD(X_train,y_train):

        model = SGDClassifier()
        param_grid = {
            'alpha': 10.0 ** -numpy.arange(1, 7),
            'loss': ['squared_loss', 'huber', 'epsilon_insensitive'],
            'penalty': ['l2', 'l1', 'elasticnet'],
            'learning_rate': ['constant', 'optimal', 'invscaling'],
            'eta0' : [1, 10, 100],
        }

        scores = ['precision'] #, 'recall']

        for score in scores:
            print("# Tuning hyper-parameters SVM for %s" % score)
            print()
            model1 = GridSearchCV(model, param_grid)
            model1.fit(X_train, y_train)
            print("Best score SGSD: " , model1.best_params_)
            print()
            print("Grid scores on development set:")
            print()
            means = model1.cv_results_['mean_test_score']
            stds = model1.cv_results_['std_test_score']
            for mean, std, params in zip(means, stds, model1.cv_results_['params']):
                print("%0.3f (+/-%0.03f) for %r"
                      % (mean, std * 2, params))
            print()

    def tuned_parameter_RF(X_train,y_train):
        model=RandomForestClassifier()
        #hyper parameters set
        params = {'criterion':['gini','entropy'],
                  'n_estimators':[10,15,20,25,30],
                  'min_samples_leaf':[1,2,3],
                  'min_samples_split':[3,4,5,6,7],
                  'random_state':[123],
                  'n_jobs':[-1]}

        scores = ['precision']#, 'recall']

        for score in scores:
            print("# Tuning hyper-parameters RF for %s" % score)
            print()

            #Making models with hyper parameters sets
            model1 = GridSearchCV(model, param_grid=params, n_jobs=-1)
            #learning
            model1.fit(X_train,y_train)
            #The best hyper parameters set
            print("Best Hyper Parameters RF:\n",model1.best_params_)

            print("Grid scores on development set:")
            print()
            means = model1.cv_results_['mean_test_score']
            stds = model1.cv_results_['std_test_score']
            for mean, std, params in zip(means, stds, model1.cv_results_['params']):
                print("%0.3f (+/-%0.03f) for %r"
                      % (mean, std * 2, params))

    def tuned_parameter_DT(X_train, y_train):
        model= DecisionTreeClassifier(random_state=1234)
        #Hyper Parameters Set
        params = {'max_features': ['auto', 'sqrt', 'log2'],
                  'min_samples_split': [2,3,4,5,6,7,8,9,10,11,12,13,14,15],
                  'min_samples_leaf':[1,2,3,4,5,6,7,8,9,10,11],
                  'random_state':[123]}

        scores = ['precision']#, 'recall']

        for score in scores:
            print("# Tuning hyper-parameters DT for %s" % score)
            print()

            #Making models with hyper parameters sets
            model1 = GridSearchCV(model, param_grid=params, n_jobs=-1)
            #Learning
            model1.fit(X_train,y_train)
            #The best hyper parameters set
            print("Best Hyper Parameters DT:",model1.best_params_)

            print("Grid scores on development set:")
            print()
            means = model1.cv_results_['mean_test_score']
            stds = model1.cv_results_['std_test_score']
            for mean, std, params in zip(means, stds, model1.cv_results_['params']):
                print("%0.3f (+/-%0.03f) for %r"
                      % (mean, std * 2, params))

    def tuned_parameter_KNN(X_train,y_train):
        model = KNeighborsClassifier(n_jobs=-1)
        #Hyper Parameters Set
        params = {'n_neighbors':[2,3,4,5,6,7,8],
                  'leaf_size':[1,2,3,5],
                  'weights':['uniform', 'distance'],
                  'algorithm':['auto', 'ball_tree','kd_tree','brute'],
                  'n_jobs':[-1]}

        scores = ['precision']#, 'recall']

        for score in scores:
            print("# Tuning hyper-parameters K-NN for %s" % score)
            print()
            #Making models with hyper parameters sets
            model1 = GridSearchCV(model, param_grid=params, n_jobs=1)
            #Learning
            model1.fit(X_train,y_train)
            #The best hyper parameters set
            print("Best Hyper Parameters K-NN:\n",model1.best_params_)

            print("Grid scores on development set:")
            print()
            means = model1.cv_results_['mean_test_score']
            stds = model1.cv_results_['std_test_score']
            for mean, std, params in zip(means, stds, model1.cv_results_['params']):
                print("%0.3f (+/-%0.03f) for %r"
                      % (mean, std * 2, params))


    def separate_label_classification(workingDir,algorithm):
        #Dividimos los vectores "etiquetados" por el algoritmo de clasificacion en CSVs
        possible_clustering = pd.read_csv(workingDir+"predict_label_evaluation_data_"+algorithm+".csv")
        df = possible_clustering.as_matrix()

        #Creamos un conjunto de datos por cluster
        data_cluster_0,data_cluster_1,data_cluster_2,data_cluster_3,data_cluster_4,data_cluster_5,data_cluster_6 = [],[],[],[],[],[],[]

        #Añadimos cada vector a su "cluster virtual"
        for i in range(len(df)):
            n_cluster = df[i,len(df[0,:])-1]
            if n_cluster == 0:
                data_cluster_0.append(df[i,:])
            elif n_cluster == 1:
                data_cluster_1.append(df[i,:])
            elif n_cluster == 2:
                data_cluster_2.append(df[i,:])
            elif n_cluster == 3:
                data_cluster_3.append(df[i,:])
            elif n_cluster == 4:
                data_cluster_4.append(df[i,:])
            elif n_cluster == 5:
                data_cluster_5.append(df[i,:])
            elif n_cluster == 6:
                data_cluster_6.append(df[i,:])

        #Ponemos la cabecera como primera fila para poder acceder a ella
        dataFrame_2 = pd.read_csv(workingDir+"label_train_data.csv",header=None)
        df_2 = dataFrame_2.as_matrix()
        df_empty = df_2[0,:]

        #Generamos un directorio para almacenar todos los vectores por algoritmo
        if not os.path.exists(workingDir+'verification_clust_'+algorithm):
            os.mkdir(workingDir+'verification_clust_'+algorithm)

        #Actualizamos la ruta para guardar ficheros
        workingDir = workingDir+'verification_clust_'+algorithm+'/'
        for i in range(7):
            if(i==0):
                #Unimos cabecera y vectores
                new_df = pd.DataFrame(data_cluster_0)
                new_df.columns = list(df_empty)
                new_df.to_csv(workingDir+'new_cluster_0.csv')
            elif(i==1):
                new_df = pd.DataFrame(data_cluster_1)
                new_df.columns = list(df_empty)
                new_df.to_csv(workingDir+'new_cluster_1.csv')
            elif(i==2):
                new_df = pd.DataFrame(data_cluster_2)
                new_df.columns = list(df_empty)
                new_df.to_csv(workingDir+'new_cluster_2.csv')
            elif(i==3):
                new_df = pd.DataFrame(data_cluster_3)
                new_df.columns = list(df_empty)
                new_df.to_csv(workingDir+'new_cluster_3.csv')
            elif(i==4):
                new_df = pd.DataFrame(data_cluster_4)
                new_df.columns = list(df_empty)
                new_df.to_csv(workingDir+'new_cluster_4.csv')
            elif(i==5):
                new_df = pd.DataFrame(data_cluster_5)
                new_df.columns = list(df_empty)
                new_df.to_csv(workingDir+'new_cluster_5.csv')
            elif(i==6):
                new_df = pd.DataFrame(data_cluster_6)
                new_df.columns = list(df_empty)
                new_df.to_csv(workingDir+'new_cluster_6.csv')


    def verify_label_classification(workingDir,algorithm):
        """
        Metodo encargado de unir los csv del primer cluster y los nuevos vectores predecidos por los algoritmos.
        Tras esto, se entrena de nuevo K-means con todos los datos juntos, siendo añadiso los nuevos vectores por el final
        y se asocia los nuevos cluster con los anteriores. Sabiendo el nº de vectores predichos y anteriores por cluster, más
        los actuales por cluster, se puede sacar la precisión media del algoritmo.
        :param workingDir:
        :param algorithm:
        :return:
        """

        #Obtenemos las cabeceras
        headers_name = pd.read_csv(workingDir+"cluster_0.csv",header=None,index_col=0)
        header_df = headers_name.as_matrix()
        header = header_df[0,:]

        join_cluster = []
        new_vectors = []
        old_vectors = []
        #Leemos los clusters que anteriormente fueron etiquetados
        for i in range(7):
            previous_cluster = pd.read_csv(workingDir+"cluster_"+str(i)+".csv",index_col=0)
            #Obtenemos el nº de vectores antiguos de cada cluster
            old_vectors.append(len(previous_cluster))

            #Unimos los vectores etiquetados por el algoritmo de clasificacion y los de clustering
            previous_df = previous_cluster.as_matrix()

            for j in range(len(previous_df)):
                join_cluster.append(previous_df[j,:])

        #Leemos los cluster que fueron predecidos
        for i in range(7):
            new_cluster = pd.read_csv(workingDir+'verification_clust_'+algorithm+'/'+"new_cluster_"+str(i)+".csv",index_col=0)
            #Obtenemos el nº de vectores nuevos del cluster
            new_vectors.append(len(new_cluster))

            #Unimos los vectores etiquetados por el algoritmo de clasificacion y los de clustering
            new_df = new_cluster.as_matrix()

            for j in range(len(new_df)):
                join_cluster.append(new_df[j,:])

        #Unimos todos los vectores en uno
        join_df = pd.DataFrame(join_cluster)
        join_df.columns = list(header)

        #Obtenemos un nuevo dataFrame pero con indice para obtener los clusters
        join_df_with_index = join_df
        join_df_with_index.to_csv(workingDir+'all_vectors.csv')

        #Establecemos IdSession como indice
        join_df.set_index(join_df["IdSession"].values, inplace=True)
        #Eliminamos esa columna de la tabla
        join_df=join_df.iloc[:,1:]

        #DataFrame con los datos predecidos por el algoritmo
        y_pred = join_df['Cluster']
        print(join_df['Cluster'])

        #Eliminamos la columna 'Cluster' y generamos un dataframe con todos los datos a clusterizar
        new_kmean = join_df.drop('Cluster',1)

        #Establecemos el nº de clusters
        kmeans = KMeans(n_clusters=7,max_iter=400)
        # Fitting the input data
        kmeans = kmeans.fit(new_kmean)
        #Predice el indice de cada muestra y lo asigna a un cluster
        labels = kmeans.predict(new_kmean)


        #Nueva columna que almacenara el nº de cluster para cada sesion
        new_colum = []

        first_idSession = []
        number_good_vectors_clustering = []
        num0,num1,num2,num3,num4,num5,num6 = 0,0,0,0,0,0,0

        join_df_with_index = join_df_with_index.as_matrix()

        #Para cada primer vector de un cluster asociamos el indice con la etiqueta del cluster para posteriormente
        #asociar cluster anterior y nuevo
        for i in range(0, len(join_df_with_index)):
            new_colum.append(kmeans.labels_[i])
            if kmeans.labels_[i] == 0:
                if num0==0:
                    first_idSession.append(0)
                    first_idSession.append(i)
                num0+=1
            elif kmeans.labels_[i] == 1:
                if num1==0:
                    first_idSession.append(1)
                    first_idSession.append(i)
                num1+=1
            elif kmeans.labels_[i] == 2:
                if num2==0:
                    first_idSession.append(2)
                    first_idSession.append(i)
                num2+=1
            elif kmeans.labels_[i] == 3:
                if num3==0:
                    first_idSession.append(3)
                    first_idSession.append(i)
                num3+=1
            elif kmeans.labels_[i] == 4:
                if num4==0:
                    first_idSession.append(4)
                    first_idSession.append(i)
                num4+=1
            elif kmeans.labels_[i] == 5:
                if num5==0:
                    first_idSession.append(5)
                    first_idSession.append(i)
                num5+=1
            elif kmeans.labels_[i] == 6:
                if num6==0:
                    first_idSession.append(6)
                    first_idSession.append(i)
                num6+=1


        join_df['Cluster']= new_colum
        print(new_colum)

        y_true = new_colum

        precision, recall, fscore, support = precision_recall_fscore_support(y_true, y_pred, average='macro')

        print('Precision: ', precision)
        print('Recall: ', recall)
        print('Fscore: ', fscore)
        print('Support: ',support)

        join_df_with_index = pd.read_csv(workingDir+"all_vectors.csv")
        #Añadimos el nº de vectores por cluster del actual k-means
        number_good_vectors_clustering.append(num0)
        number_good_vectors_clustering.append(num1)
        number_good_vectors_clustering.append(num2)
        number_good_vectors_clustering.append(num3)
        number_good_vectors_clustering.append(num4)
        number_good_vectors_clustering.append(num5)
        number_good_vectors_clustering.append(num6)

        precision = 0.0

        for i in range(7):
            current_cluster = first_idSession[i*2]
            current_idSession_cluster = first_idSession[i*2+1]
            previo_cluster = join_df_with_index.iloc[current_idSession_cluster]['Cluster']

            FP = (new_vectors[int(previo_cluster)]+old_vectors[int(previo_cluster)]) - number_good_vectors_clustering[int(current_cluster)]
            if(FP < 0):
                FP = 0
            TP = number_good_vectors_clustering[int(current_cluster)]
            current_precision = TP / (TP+FP)
            precision+=current_precision
            #print('TP:',TP)
            #print('FP:',FP)
            #print('old vector:',old_vectors[int(previo_cluster)])
            #print('new vector:',new_vectors[int(previo_cluster)])
            #print('*********************')
        precision = precision/7
        print('Precision calculada: '+algorithm,precision)

        #print('Cluster Ahora 0:',num0,'Cluster 1:',num1,'Cluster 2:',num2,'Cluster 3:',num3,'Cluster 4:',num4,'Cluster 5:',num5,'Cluster 6:',num6)

    def read_CSV(workingDir):
        #Borrar la columna del index
        dataFrame = pd.read_csv(workingDir+"train_data.csv",index_col=0)

        #Establecemos el index como el IdSession
        dataFrame.set_index(dataFrame["IdSession"].values, inplace=True)
        #Eliminamos esa columna de la tabla
        dataFrame=dataFrame.iloc[:,1:]
        return dataFrame

    def delete_column_IdSession(dataFrame):
        #Establecemos el index como el IdSession
        dataFrame.set_index(dataFrame["IdSession"].values, inplace=True)
        #Eliminamos esa columna de la tabla
        dataFrame=dataFrame.iloc[:,1:]
        return dataFrame


    def hyperparameter_UMAP(self, workingDir) -> NoReturn:
        data = self.read_CSV(workingDir)
        for n in (2, 5, 10, 20, 50, 100, 200):
            embbeding = umap.UMAP(n_neighbors=n).fit_transform(data)
            self.hyperparameter_kmeans(workingDir, embbeding, 'n_neighbors = {}'.format(n))
            #draw_umap(workingDir, data, n_neighbors=n, title='n_neighbors = {}'.format(n))

        for d in (0.0, 0.1, 0.25, 0.5, 0.8, 0.99):
            embbeding = umap.UMAP(min_dist=d).fit_transform(data)
            self.hyperparameter_kmeans(workingDir, embbeding, 'min_dist = {}'.format(d))
            #draw_umap(workingDir, data, min_dist=d, title='min_dist = {}'.format(d))

        for m in ("euclidean", "manhattan"):
            name = m if type(m) is str else m.__name__
            embbeding = umap.UMAP(metric=m).fit_transform(data)
            self.hyperparameter_kmeans(workingDir, embbeding, 'metric = {}'.format(name))
            #draw_umap(workingDir, data, n_components=2, metric=m, title='metric = {}'.format(name))

    def draw_umap(workingDir, data, n_neighbors=15, min_dist=0.1, n_components=2, metric='euclidean', title=''):
        fit = umap.UMAP(
            n_neighbors=n_neighbors,
            min_dist=min_dist,
            n_components=n_components,
            metric=metric
        )

        u = fit.fit_transform(data);

        if n_components == 1:
            plt.scatter(u[:,0], range(len(u)), c=data)
        if n_components == 2:
            plt.scatter(u[:,0], u[:,1], c=data)
        if n_components == 3:
            plt.scatter(u[:,0], u[:,1], u[:,2], c=data)
        plt.title(title, fontsize=18)

        if not os.path.exists(workingDir+'hyperparameter_umap'):
            os.mkdir(workingDir+'hyperparameter_umap')
            plt.savefig(workingDir+'hyperparameter_umap/'+title+'.png')
        else:
            plt.savefig(workingDir+'hyperparameter_umap/'+title+'.png')

        plt.clf()


    def hyperparameter_kmeans(self, workingDir, embbeding, title_umap) -> NoReturn:

        # Calcular previamente el metodo del codo para saber que valores indicar
        for n in (6, 7):
            self.draw_kmeans(workingDir, embbeding, n_clusters=n, title=title_umap+'n_clusters = {}'.format(n))

        for d in (10, 20, 30):
            self.draw_kmeans(workingDir, embbeding, n_init=d, title=title_umap+'n_init = {}'.format(d))

        for m in (300, 400, 500):
            self.draw_kmeans(workingDir, embbeding, max_iter=m, title=title_umap+'max_iter = {}'.format(m))


    def draw_kmeans(self, workingDir, data, n_clusters = 7, init='k-means++', n_init=10, max_iter=300, title='') -> NoReturn:
        kmeans = KMeans(n_clusters=n_clusters, init=init, n_init=n_init, max_iter=max_iter)
        #Fitting the input data
        kmeans = kmeans.fit(data)
        #Predice el indice de cada muestra y lo asigna a un cluster
        labels = kmeans.predict(data)

        #Centroid values
        centroids = kmeans.cluster_centers_

        #Identificacion de cada cluster en la grafica
        for i in range(0, len(data)):
            if kmeans.labels_[i] == 0:
                c0 = plt.scatter(data[i,0],data[i,1],c='g')
            elif kmeans.labels_[i] == 1:
                c1 = plt.scatter(data[i,0],data[i,1],c='r')
            elif kmeans.labels_[i] == 2:
                c2 = plt.scatter(data[i,0],data[i,1],c='c')
            elif kmeans.labels_[i] == 3:
                c3 = plt.scatter(data[i,0],data[i,1],c='m')
            elif kmeans.labels_[i] == 4:
                c4 = plt.scatter(data[i,0],data[i,1],c='y')
            elif kmeans.labels_[i] == 5:
                c5 = plt.scatter(data[i,0],data[i,1],c='k')
            elif kmeans.labels_[i] == 6:
                c6 = plt.scatter(data[i,0],data[i,1],c='b')
        if(n_clusters==6):
            plt.legend([c0, c1, c2, c3, c4,c5],['Cluster 0','Cluster 1','Cluster 2','Cluster 3','Cluster 4','Cluster 5'])
        elif(n_clusters==7):
            plt.legend([c0, c1, c2, c3, c4,c5,c6],['Cluster 0','Cluster 1','Cluster 2','Cluster 3','Cluster 4','Cluster 5','Cluster 6'])

        plt.scatter(centroids[:, 0], centroids[:, 1], marker='*', c='black', s=50)
        plt.title('K-means clusters'+title, fontsize=18)

        if not os.path.exists(workingDir+'hyperparameter_umap_kmeans'):
            os.mkdir(workingDir+'hyperparameter_umap_kmeans')
            plt.savefig(workingDir+'hyperparameter_umap_kmeans/'+title+'.png')
        else:
            plt.savefig(workingDir+'hyperparameter_umap_kmeans/'+title+'.png')

        plt.clf()

def CreateArgParser() -> argparse:
    """
    Metodo para establecer los argumentos que necesita la clasek
    :return:
    """
    config = configparser.ConfigParser()
    config.sections()
    config.read('settings.conf')

    example = "\n\tExample of use to execute the ML: python3 machineLearning.py -d /mnt/cowrie/ -o output/ -v"

    myParser = argparse.ArgumentParser(description='%(prog)s is a script to apply ML.', usage='{}'.format(example))

    myParser.add_argument('-d', '--dir', help='Directory where the files are located.')
    myParser.add_argument('-f', '--file', help='File CSV.')
    return myParser.parse_args()


if __name__ == "__main__":

    arg = CreateArgParser()
    #logger = getLogger(arg.verbose, 'elk')

    ml = MachineLearning()


    if arg.dir is not None:
        start = timer()

        #ml.request_objets_elastichsearch(arg.dir)
        #ml.JSONToCSV(arg.dir)
        ml.clasificador(arg.dir)
        #ml.onehotEncoding(arg.dir)
        """
        Saber el número de cluster para modificar parametros de la funcion clustering y draw_kmeans
        """
        #ml.elbowMethod(arg.dir)
        #ml.hyperparameter_UMAP(arg.dir)
        """
        Verificar que tras ajustar los parametros de UMAP no ha cambiado el k optimo
        """
        #ml.elbowMethod(arg.dir)
        """
        Indicar los parametros apropiados de UMAP tras analizarlos 
        para el siguiente metodo
        Saber el número de cluster para modificar parametros de la funcion clustering y draw_kmeans
        """
        #ml.clustering(arg.dir)
        """
        Modificar parametros Soporte,Confidence y Lift tras ver los vectores de cada cluster
        """
        #ml.new_apriori_algorithm(arg.dir)
        #ml.labeled_IdSession(arg.dir)
        #ml.separate_label_classification(arg.dir,'svm')
        #ml.verify_label_classification(arg.dir,'svm')
        #ml.separate_label_classification(arg.dir,'knn')
        #ml.verify_label_classification(arg.dir,'knn')
        #ml.separate_label_classification(arg.dir,'dt')
        #ml.verify_label_classification(arg.dir,'dt')

        end = timer()
print('Tiempo total: {}'.format(end - start))