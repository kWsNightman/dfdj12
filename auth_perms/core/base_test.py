import sys
import inspect
import traceback


class BaseTest:
    def run(self):
        methods = inspect.getmembers(self, inspect.ismethod)

        for method_name, _ in methods:
            if not method_name.startswith('test_'):
                continue

            test_method = getattr(self, method_name)

            output_begin = self.__class__.__name__ + '.' + method_name + \
                (f' ({test_method.__doc__})' if test_method.__doc__ else '') + ' ...'

            try:
                test_method()
            except AssertionError as err:  # FAILED TEST
                print(output_begin, '\033[31mFAILED\033[0m', (f'- {str(err)}' if str(err) else ''))

                _, _, tb = sys.exc_info()
                filename, line, func, text = traceback.extract_tb(tb)[-1]

                print(f'In file {filename}:\n    function {func} on line {line}:\n        {text}')
            else:  # SUCCESSFUL TEST
                print(output_begin, '\033[32mSUCCESS\033[0m')
