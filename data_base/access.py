import pandas as pd
import os

DB_FILE = "db.csv"

class DatabaseEmptyError(Exception):
    """Custom exception raised when the database is empty."""
    pass


def load_db():
    """
    Load the database CSV if it exists, otherwise raise an exception.

    Returns:
        pd.DataFrame: The loaded database.

    Raises:
        DatabaseEmptyError: If the database file is not found or is empty.
    """
    if os.path.exists(DB_FILE) and os.path.getsize(DB_FILE) > 0:
        db = pd.read_csv(DB_FILE)
        if db.empty:
            raise DatabaseEmptyError("Database is empty.")
        return db
    else:
        raise DatabaseEmptyError("Database file not found or empty.")


def combine_csv_files(folder_path):
    """
    Combine all CSV files in a folder into db.csv (order of columns doesn't matter).

    Parameters:
        folder_path (str): Path to the folder containing CSV files.

    Returns:
        tuple: (number of files combined (int), total number of rows after combining (int))
    """
    all_files = [os.path.join(folder_path, f) for f in os.listdir(folder_path) if f.endswith(".csv")]
    combined_df = pd.DataFrame()

    for file in all_files:
        df = pd.read_csv(file)
        combined_df = pd.concat([combined_df, df], ignore_index=True)

    combined_df.drop_duplicates(inplace=True)
    combined_df.reset_index(drop=True, inplace=True)
    combined_df.to_csv(DB_FILE, index=False)
    return len(all_files), len(combined_df)


def add_data(new_data_csv):
    """
    Add new data from a CSV file (avoid duplicates).

    Parameters:
        new_data_csv (str): Path to the new CSV file to add.

    Returns:
        int: Total number of rows after adding new data.
    """
    try:
        db = load_db()
    except DatabaseEmptyError:
        db = pd.DataFrame()

    new_data = pd.read_csv(new_data_csv)
    combined = pd.concat([db, new_data], ignore_index=True).drop_duplicates()
    combined.to_csv(DB_FILE, index=False)
    return len(combined)


def search_data(column_name, value):
    """
    Search for rows where given column matches a value (case-insensitive).

    Parameters:
        column_name (str): The column to search in.
        value (str): The value to search for.

    Returns:
        pd.DataFrame: DataFrame containing matching rows.

    Raises:
        KeyError: If the column is not found in the database.
    """
    db = load_db()
    if column_name not in db.columns:
        raise KeyError(f"Column '{column_name}' not found in database.")

    result = db[db[column_name].astype(str).str.lower() == str(value).lower()]
    return result


def delete_data(column_name, value):
    """
    Delete rows based on column value.

    Parameters:
        column_name (str): The column to match for deletion.
        value (str): The value to match for deletion.

    Returns:
        tuple: (number of records deleted (int), number of records remaining (int))

    Raises:
        KeyError: If the column is not found in the database.
    """
    db = load_db()
    if column_name not in db.columns:
        raise KeyError(f"Column '{column_name}' not found in database.")

    before = len(db)
    db = db[db[column_name].astype(str).str.lower() != str(value).lower()]
    after = len(db)
    db.to_csv(DB_FILE, index=False)
    return before - after, after


# --- User Interaction ---
if __name__ == "__main__":
    print("""
CSV Manager Options:
1. Combine all CSVs in folder
2. Add data from new CSV
3. Search data
4. Delete data
5. Exit
""")

    while True:
        choice = input("Enter your choice (1-5): ").strip()

        try:
            if choice == "1":
                folder = input("Enter folder path containing CSV files: ").strip()
                files_count, total_rows = combine_csv_files(folder)
                print(f"Combined {files_count} CSV file(s) into {DB_FILE}. Total rows: {total_rows}.")

            elif choice == "2":
                path = input("Enter CSV file path to add: ").strip()
                total_rows = add_data(path)
                print(f"Added data from {path} to {DB_FILE}. Total rows: {total_rows}.")

            elif choice == "3":
                col = input("Enter column name to search: ").strip()
                val = input("Enter value to search for: ").strip()
                results = search_data(col, val)
                if results.empty:
                    print("No matching records found.")
                else:
                    print(f"Found {len(results)} matching record(s):")
                    print(results)

            elif choice == "4":
                col = input("Enter column name for deletion: ").strip()
                val = input("Enter value to delete: ").strip()
                deleted, remaining = delete_data(col, val)
                print(f"Deleted {deleted} record(s). Remaining: {remaining}.")

            elif choice == "5":
                print("Exiting.")
                break

            else:
                print("Invalid choice. Please select between 1–5.")

        except DatabaseEmptyError as e:
            print(f"Error: {e}")
        except KeyError as e:
            print(f"Error: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")
