"""Project CLI."""
import sys
import argparse

from utils.general_utils import ModelUtils

from settings import PROJECT_ROOT

sys.path.append(PROJECT_ROOT)


class MainCLI:
    """
    Summary:
        Command-line interface.
    """
    def __init__(self):
        self.args = None
        self.parser = argparse.ArgumentParser(description='CLI.')

    def __call__(self, *args, **kwds):
        self.set_arguments()
        self.check_main_action()

    def set_arguments(self):
        """
        Summary:
            Set available options.
        """
        self.parser.description = (
            "Next options currently available for use:"
        )
        self.parser.add_argument(
            "-t",
            "--train",
            default=False,
            action=argparse.BooleanOptionalAction,
            help="Train model with provided data. "
                 "Example: python cli.py -t"
        )
        self.parser.add_argument(
            "-u",
            "--update",
            default=False,
            action=argparse.BooleanOptionalAction,
            help="Update model data. "
                 "Example: python cli.py -u"
        )
        self.parser.add_argument(
            "-l",
            "--link",
            help="Test link."
                 "Example: -l 'https://example.com' "
                 "Example: -l 'https://example.com/products.php?linkcomplet=iphone-6-plus-apple-64gb-cinza-espacial-tele-5-5-retin-4g-camera-8mp-frontal-ios-10-proc.-m8/p/2116558/te/ipho/&amp;id=10'"
        )
        self.parser.add_argument(
            "-c",
            "--check",
            default=False,
            action=argparse.BooleanOptionalAction,
            help="Check model accuracy."
                 "Example: python cli.py -c"
        )
        self.args = self.parser.parse_args()


    def check_main_action(self):
        """
        Summary:
            Check which action user selected:
            get additional information,
            create report,
            get general information.
        """
        if self.args.train:
            ModelUtils.train_model()
        elif self.args.update:
            ModelUtils.train_model(update=True)
        elif self.args.link:
            ModelUtils.test_url(self.args.link, console=True)
        elif self.args.check:
            ModelUtils.check_model_accuracy()
        else:
            print(
                "For Linux, iOS. Write: python3 cli.py --help \n"
                "For Windows. Write: python cli.py --help \n"
                "For virtual environments. Write: python cli.py --help \n"
                "to check available options. \n"
                "You can use only one flag at the same time!"
            )


if __name__ == '__main__':
    init_cli = MainCLI()
    init_cli()
