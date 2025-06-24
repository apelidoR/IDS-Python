import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os

st.title("Gráfico de Rede")

# Passo 1: Definindo a pasta e listando os arquivos CSV
folder_path = "/home/hugi/Projects/IDS_project/IDS_Python/Dados"  
if not os.path.exists(folder_path):
    st.error("A pasta especificada não existe. Verifique o caminho.")
else:
    csv_files = [f for f in os.listdir(folder_path) if f.endswith('.csv')]
    
    if not csv_files:
        st.warning("Nenhum arquivo CSV encontrado na pasta.")
    else:
        # Criando uma lista suspensa para selecionar o arquivo
        selected_file = st.selectbox("Selecione o arquivo .CSV", csv_files)
        
        if selected_file:
            # Carregando o arquivo selecionado
            file_path = os.path.join(folder_path, selected_file)
            df = pd.read_csv(file_path)
            st.write("Arquivos carregados: ", df.head())

            # Passo 2: Agrupando dados
            contagem = df[df.columns[6]].value_counts()
            st.write("Total por categoria: ", contagem)

            # Passo 3: Montando gráfico
            # Design
            cor = ['#88eed0', '#cae081', '#f2cd4f', '#f68b36', '#ef4335']
            sizes = contagem.values
            texto = contagem.index
            expandir = [0.1 if i == 0 else 0 for i in range(len(texto))]

            fig, ax = plt.subplots()
            ax.pie(sizes,
                   labels=texto,
                   autopct='%1.1f%%',
                   startangle=90,
                   colors=cor[:len(texto)],
                   pctdistance=0.8,
                   labeldistance=1.1)
            ax.axis("equal")

            # Passo 4: Imprimindo gráfico na tela
            st.pyplot(fig)