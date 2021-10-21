import os

from flask import current_app as app
from flask_script import Manager


translate_manager = Manager(usage="Use translate commands")


def get_path(exclude_directories):
    """
    Walk over project dirictories to collect all received in params folders
    :param: folder_name - folder name what we looking for
    """

    files_paths = list()

    for root, dirs, files in os.walk("."):
        for directory in exclude_directories:
            try:
                dirs.remove(directory)
            except ValueError:
                pass

        if root == '.':
            files_paths.append(
                root.lstrip('./'))
            for file in files:
                if file.endswith('.py'):
                    files_paths.append(file)
        else:
            files_paths.append(
                root.lstrip('./'))
        
    return files_paths


@translate_manager.option('--directory', '-d', dest="directory", default=None, required=False,
                          help="Directory where are .po files located.")
def compile(directory):
    """
    Compile translations in your app. Additional parameter is --directory or -d. Where is your .po files are located.
    """
    if not directory:
        if app.config.get('BABEL_TRANSLATION_DIRECTORIES', None):
            directory = app.config.get('BABEL_TRANSLATION_DIRECTORIES').split(';')[:-1] \
                if app.config.get('BABEL_TRANSLATION_DIRECTORIES').endswith(';') else \
                app.config.get('BABEL_TRANSLATION_DIRECTORIES').split(';')
        else:
            directory = ['localization']

    else:
        directory = [directory]
    try:
        for d in directory:
            os.system("pybabel compile -d %s" % d)
    except Exception as e:
        print('#' * 15, 'ERROR', '#' * 15)
        print('Some error occurred while compiling translations in directory - %s! \n Exception - %s' % (directory, e))
        print('#' * 35)
    return


@translate_manager.option('--directory', '-d', dest="directory", default='localization', required=False,
                          help="Directory where are .po files located.")
@translate_manager.option('--path', '-p', dest="path", default='.', required=False,
                          help="Directories where we should search messages for translate.")
@translate_manager.option('--config', '-cfg', dest="config", default='../babel.cfg', required=False,
                          help="Path to babel config file.")
@translate_manager.option('--exclude', '-e', dest="exclude_directories", default='', required=False,
                          help="Exclude directories path. Default empty.")
def update(path, config, directory, exclude_directories):
    """
    Update all languages not translated values.
    """
    if (not path or path == '.') and exclude_directories:
        exclude_directories = exclude_directories.split(',')
        files_path = get_path(exclude_directories)
        path = str()
        for translate_dir in files_path:
            if translate_dir == '':
                continue

            path += ' ' + translate_dir

    try:
        os.system('pybabel extract -F %s -k _l -k _ -o messages.pot %s' % (config, path))
    except Exception as e:
        print('#' * 15, 'ERROR', '#' * 15)
        print('Some error occurred while extracting translations in path - %s! \n Exception - %s' % (path, e))
        print('#' * 35)
        return

    try:
        os.system('pybabel update -i messages.pot -d %s' % directory)
    except Exception as e:
        print('#' * 15, 'ERROR', '#' * 15)
        print('Some error occurred while compiling translations in directory - %s! \n Exception - %s' % (directory, e))
        print('#' * 35)

    os.remove('messages.pot')


@translate_manager.option('--directory', '-d', dest="directory", default='localization', required=False,
                          help="Directory where are .po files located.")
@translate_manager.option('--path', '-p', dest="path", default='.', required=False,
                          help="Directories where we should search messages for translate.")
@translate_manager.option('--config', '-cfg', dest="config", default='../babel.cfg', required=False,
                          help="Path to babel config file.")
@translate_manager.option('--language', '-l', dest="language", required=True,
                          help="Language code. Like en - English, ru - Russian etc. Use two symbol code")
def init(language, path, config, directory):
    """
    Initialize a new language. Creates directory for your language.
    """
    try:
        os.system('pybabel extract -F %s -k _l -k _ -o messages.pot %s' % (config, path))
    except Exception as e:
        print('#' * 15, 'ERROR', '#' * 15)
        print('Some error occurred while extracting translations in path - %s! \n Exception - %s' % (path, e))
        print('#' * 35)
        return

    try:
        os.system('pybabel init -i messages.pot -d %s -l %s' % (directory, language))
    except Exception as e:
        print('#' * 15, 'ERROR', '#' * 15)
        print('Some error occurred while initialize directory - %s for language - %s! \n Exception - %s' %
              (path, language, e))
        print('#' * 35)

    os.remove('messages.pot')
