from dominate.tags import style


def report_styling():
    return style(
        """
        .container-table {
            display: grid; /* Use CSS Grid */
            place-items: center; /* Center both horizontally and vertically */
        }

        .full-width {
            width: 100%
        }

        .my_table {
            width: 100%;
            border-collapse: collapse;
        }

        .my_table th, .my_table td {
            border: 1px solid black;
            text-align: left;
            padding: 8px;
        }
        .my_table th {
            background-color: #f2f2f2;
        }
        #myImage {
            display: block;
            margin-left: auto;
            margin-right: auto;
            width: 75%; /* or any desired width */
            height: auto; /* to maintain the aspect ratio */
        }
        .centered-table {
            margin-left: auto;
            margin-right: auto;
        }

        table {
            border-collapse: collapse;
            width: 50%;
        }
        th, td {
            border: 1px solid black;
            text-align: left;
            padding: 8px;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f2f2f2;
        }
        .grade-A {
            background-color: green;
            color: white; /* For better readability */
        }
        .grade-B {
            background-color: yellow;
            color: black; /* Adjust color for readability */
        }
        .grade-C {
            background-color: orange;
            color: white;
        }
        .grade-D {
            background-color: red;
            color: white;
        }
        .grade-F {
            background-color: darkred;
            color: white;
        }
        .break-after {
            page-break-after: always;
        }

        td.divider-cell {
            width: 1
        }

        td.center-text {
            text-align: center; 
        }
        @page {
            size: letter landscape;
            margin: 2cm;
        }
        """
    )


def security_grade_class(grade):
    if grade == "N/A":
        return "grade-none"
    return "grade-" + grade
