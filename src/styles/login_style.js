import { StyleSheet } from 'react-native';
const styles = StyleSheet.create({
    container: {
      flex: 1,
      backgroundColor: '#fff',
      alignItems: 'center',
      justifyContent: 'center',
      padding: 20,
    },
    title: {
      fontSize: 24,
      fontWeight: 'bold',
      marginBottom: 30,
    },
    input: {
      width: '100%',
      height: 50,
      backgroundColor: '#f2f2f2',
      borderRadius: 5,
      paddingHorizontal: 15,
      marginBottom: 20,
      fontSize: 16,
      color: '#000',
    },
    loginButton: {
      width: '100%',
      height: 50,
      backgroundColor: '#ff6b3c',
      justifyContent: 'center',
      alignItems: 'center',
      borderRadius: 5,
      marginBottom: 20,
    },
    loginButtonText: {
      color: '#fff',
      fontSize: 18,
      fontWeight: 'bold',
    },
    orText: {
      marginVertical: 10,
      fontSize: 16,
      color: '#555',
    },
    googleButton: {
      width: '100%',
      height: 50,
      borderWidth: 1,
      borderColor: '#ddd',
      justifyContent: 'center',
      alignItems: 'center',
      borderRadius: 5,
      marginBottom: 20,
      flexDirection: 'row',
    },
    googleButtonText: {
      fontSize: 18,
      color: '#4285F4',
      fontWeight: 'bold',
    },
    footerText: {
      fontSize: 14,
      color: '#555',
    },
    signUpText: {
      color: '#ff6b3c',
      fontWeight: 'bold',
    },
  });

  export default styles;