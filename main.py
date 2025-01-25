from encription import ui
from gui import gui

if __name__ == '__main__':
    print('HELLO! What would you like to use?')
    option = 2
    while option != 3:
        print('1. gui')
        print('2. ui')
        print('3. exit')

        option = int(input('Enter your option: '))
        if option == 1:
            gui()
        elif option == 2:
            ui()
        elif option == 3:
            break
        else:
            print('Invalid option')