import streamlit as stl
import pandas as pd 
import matplotlib.pyplot as mpl

stl.title("Grafico de rede")

#Passo 1: importando os arquivos CSV
up_file = stl.file_uploader ("Seleciona o arquivo .CSV", type=["csv"])
if up_file:
    df = pd.read_csv(up_file)
    stl.write("Arquivos carregados: ", df.head())

    #Passo 2: agrupando dados 
    contagem = df[df.columns[6]].value_counts()
    stl.write("Total por categoria: ", contagem)

    #Passo 3: Motando grafico
        #Design
    cor = ['#88eed0', '#cae081', '#f2cd4f', '#f68b36', '#ef4335']
    sizes = contagem.values
    texto = contagem.index
    expandir = [0.1 if i==0 else 0 for i in range(len(texto)) ]

    fig, ax = mpl.subplots()
    ax.pie(sizes,
           labels=texto,
           autopct='%1.1f%%',
           startangle=90,
           colors=cor[:len(texto)],
           pctdistance=0.8,
           labeldistance=1.1
           )
    ax.axis("equal")

    #Passo 4: imprimindo grafico na tela
    stl.pyplot(fig)

 


    


    







