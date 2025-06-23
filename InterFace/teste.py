import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.colors

# Exemplo simples
data = {
    'Categoria': ['A', 'B', 'C'],
    'Contagem': [10, 20, 30],
    'Porcentagem (%)': [16.7, 33.3, 50.0]
}
df = pd.DataFrame(data)

# Gera paleta
cores = plt.get_cmap('tab20').colors[:len(df)]
css = [f'background-color: {matplotlib.colors.to_hex(c)}' for c in cores]
df['Cor'] = css

# Aplicando estilo
styled = df.style.apply(lambda _: df['Cor'], axis=0)  # sem remoção
st.dataframe(styled)

styled2 = styled.hide(subset=['Cor'], axis='columns')
st.dataframe(styled2)