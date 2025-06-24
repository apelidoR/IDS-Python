import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.colors
import os

st.title("Gráfico de Rede")

# Passo 1: Definindo a pasta e listando os arquivos CSV
folder_path = "../Dados"  # Substitua pelo caminho da sua pasta
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
            col_categoria = df.columns[6] 
            contagem = df[col_categoria].value_counts()
            st.table(contagem.rename_axis("Categoria").reset_index(name="Contagem"))

            # Passo 3: Montando gráfico
                # Design
            sizes = contagem.values
            texto = contagem.index
            percent = (contagem/ contagem.sum()*100).round(1)
            expandir = [0.1 if i == 0 else 0 for i in range(len(texto))]
                # Inserindo os dados para tebela
            resultado = pd.DataFrame({
                'Categoria': contagem.index,
                'Contagem': contagem.values,
                'Porcentagem (%)': percent.values
            })
                # Gerando as cores
            cor = plt.get_cmap('tab20').colors[:len(texto)]
            resultado['cor'] = [f'background-color: {matplotlib.colors.to_hex(c)}' for c in cor]

            # Colunas
            col1, col2 = st.columns([1,1])
            
            with col1:
                fig, ax = plt.subplots()

                wedges, texts = ax.pie(sizes,
                    labels=None,
                    startangle=90,
                    colors=cor,
                    pctdistance=0.8,
                    explode = expandir)
                

                    # pizza anel
                centro_circulo = plt.Circle((0,0), 0.70, fc = 'white')
                fig.gca().add_artist(centro_circulo)
                ax.axis("equal")


                # Passo 4: Imprimindo gráfico na tela
                st.pyplot(fig)

                # Passo 5: Tabela do grafico
                with col2:
                    # Cores na tabela 
                    styled = resultado.style.apply(
                        lambda _: resultado['cor'], axis=0
                    ).hide_columns(['cor'])
                    st.dataframe(styled, use_container_width=True, height=400)

                    # Legenda visual
                    legenda = ""
                    for cor, cat in zip (cor, texto):
                        hexc = matplotlib.colors.to_hex(cor)
                        legenda +=(
                            f"<div style='display:inline-block;"
                            f"width:15px; height:15px; background:{hexc};"
                            f"margin-right:5px;'></div>{cat}&nbsp;&nbsp;"
                        )
                    st.markdown(legenda, unsafe_allow_html=True)